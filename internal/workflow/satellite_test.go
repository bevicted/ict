package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bevicted/ict/internal/config"
	"github.com/bevicted/ict/internal/prompt"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

func TestSatelliteLifecyclePersistsWithoutPublicKeyLeak(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "state", "ict", "terraform")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	runner.Terminal = func() bool { return true }
	t.Setenv("PATH", t.TempDir())
	inputs := configuredSatelliteInputs(t)
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	key, err := readSSHPublicKey(inputs.SatelliteSSHPublicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	contextBytes, err := os.ReadFile(filepath.Join(workspace, ictterraform.ContextName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contextBytes), key) {
		t.Fatal("recovery context contains SSH public key")
	}
	tfvars, err := os.ReadFile(filepath.Join(workspace, ictterraform.TFVarsName))
	if err != nil || !strings.Contains(string(tfvars), key) {
		t.Fatal("private tfvars do not contain the selected SSH public key")
	}
	if !strings.Contains(string(contextBytes), "vpc.us-south.example.invalid") {
		t.Fatal("Satellite recovery context did not retain the regional VPC endpoint")
	}
	writeTerraformState(t, workspace)
	fake.resources = true
	if err := runner.Create(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	changed := inputs
	changed.SatelliteHostImage = "rhel-9-synthetic"
	fake.calls = nil
	if err := runner.Create(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
		t.Fatalf("mismatched Satellite create error = %v", err)
	}
	if got := strings.Join(terraformActions(t, fake.calls), ", "); got != "init, state list" {
		t.Fatalf("mismatched Satellite actions = %q", got)
	}
	fake.calls = nil
	if err := runner.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.calls[len(fake.calls)-1], " "); !strings.Contains(got, "destroy -input=false -auto-approve") {
		t.Fatalf("Satellite destroy did not run: %q", got)
	}
}

func TestSatelliteDestroyRejectsModifiedSSHPublicKey(t *testing.T) {
	workspace := t.TempDir()
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredSatelliteInputs(t)
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}

	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	data, err := os.ReadFile(tfvarsPath)
	if err != nil {
		t.Fatal(err)
	}
	var values Values
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	values.SatelliteSSHPublicKey = strings.Replace(values.SatelliteSSHPublicKey, "synthetic-comment", "modified-comment", 1)
	data, err = json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tfvarsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	fake.resources = true
	fake.calls = nil
	if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
		t.Fatalf("destroy after SSH public-key modification = %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("destroy after SSH public-key modification called Terraform: %#v", fake.calls)
	}
}

func TestSatelliteValidationAndDefaults(t *testing.T) {
	tests := map[string]struct {
		mutate func(*Inputs)
		want   string
	}{
		"requires OpenShift":      {mutate: func(in *Inputs) { in.Platform = "kubernetes" }, want: "requires the openshift platform"},
		"requires three zones":    {mutate: func(in *Inputs) { in.SatelliteZones = in.SatelliteZones[:2] }, want: "satellite-zone"},
		"requires distinct zones": {mutate: func(in *Inputs) { in.SatelliteZones[2] = in.SatelliteZones[1] }, want: "must be distinct"},
		"requires one region":     {mutate: func(in *Inputs) { in.SatelliteZones[2] = "eu-gb-1" }, want: "one region"},
		"worker fallback only":    {mutate: func(in *Inputs) { in.WorkerCount = 2 }, want: "one or three"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inputs := configuredSatelliteInputs(t)
			test.mutate(&inputs)
			cfg, err := config.Load(inputs.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = newRunner(t.TempDir(), &fakeTerraform{}).resolve(context.Background(), cfg, inputs)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Satellite validation error = %v, want %q", err, test.want)
			}
		})
	}
	inputs := configuredSatelliteInputs(t)
	inputs.SatelliteHostProfile, inputs.SatelliteWorkerOperatingSystem = "", ""
	inputs.SatelliteZones = []string{"us-south-ngdc-test-1", "us-south-ngdc-test-2", "us-south-ngdc-test-3"}
	cfg, err := config.Load(inputs.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	values, target, err := newRunner(t.TempDir(), &fakeTerraform{}).resolve(context.Background(), cfg, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if values.WorkerCount != 1 || values.SatelliteHostProfile != "bx2-4x16" || values.SatelliteWorkerOperatingSystem != "RHCOS" || target.Endpoints.VPC != "https://vpc.us-south-ngdc-test.example.invalid" {
		t.Fatalf("Satellite defaults or regional endpoint are incorrect")
	}
	inputs.WorkerCount = 3
	values, _, err = newRunner(t.TempDir(), &fakeTerraform{}).resolve(context.Background(), cfg, inputs)
	if err != nil || values.WorkerCount != 3 {
		t.Fatalf("Satellite three-worker fallback = %d, %v", values.WorkerCount, err)
	}
}

func TestSatelliteInteractiveDiscoveryAndMissingInputBehavior(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "fzf-called")
	fzf := filepath.Join(bin, "fzf")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + marker + "\"\ncase \"$*\" in *--multi*) while IFS= read -r value; do printf '%s\\n' \"$value\"; done ;; *) IFS= read -r value; printf '%s\\n' \"$value\" ;; esac\n"
	if err := os.WriteFile(fzf, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(t.TempDir(), fake)
	runner.Terminal = func() bool { return true }
	runner.IBMCloud = discovery
	inputs := configuredSatelliteInputs(t)
	inputs.Platform, inputs.Version, inputs.ResourceGroup = "", "", ""
	inputs.SatelliteManagedFrom, inputs.SatelliteHostImage, inputs.SatelliteZones = "", "", nil
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil || len(discovery.environs) == 0 {
		t.Fatal("Satellite omissions did not invoke conditional fzf and JSON discovery")
	}
	hostProfilesDiscovered := false
	for _, call := range discovery.calls {
		if strings.Join(call, " ") == "is instance-profiles --output json" {
			hostProfilesDiscovered = true
			break
		}
	}
	if !hostProfilesDiscovered {
		t.Fatal("Satellite omissions did not discover and select a host profile")
	}
	prompts, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(prompts), "--prompt=Satellite worker operating system> ") {
		t.Fatal("Satellite omissions did not select a worker operating system")
	}

	runner = newRunner(t.TempDir(), &fakeTerraform{})
	runner.Terminal = func() bool { return false }
	inputs = configuredSatelliteInputs(t)
	inputs.SatelliteHostImage = ""
	err = runner.Plan(context.Background(), inputs)
	var missing *prompt.MissingInputError
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), "satellite-host-image") {
		t.Fatalf("non-interactive Satellite missing input error = %v", err)
	}

	t.Setenv("PATH", t.TempDir())
	runner.Terminal = func() bool { return true }
	err = runner.Plan(context.Background(), inputs)
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), "satellite-host-image") {
		t.Fatalf("no-fzf Satellite missing input error = %v", err)
	}
}

func TestSatelliteTargetAndMissingInputFailBeforeExecution(t *testing.T) {
	inputs := configuredSatelliteInputs(t)
	content, err := os.ReadFile(inputs.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputs.ConfigPath, []byte(strings.Replace(string(content), ", satellite", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(t.TempDir(), fake)
	runner.Terminal = func() bool { return true }
	runner.IBMCloud = discovery
	if err := runner.Plan(context.Background(), inputs); err == nil || !strings.Contains(err.Error(), "does not support provider") {
		t.Fatalf("unsupported Satellite target error = %v", err)
	}
	if len(fake.calls) != 0 || len(discovery.environs) != 0 {
		t.Fatalf("unsupported Satellite target executed dependencies")
	}
}

func TestSatelliteSSHInputValidation(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key.pub")
	for name, contents := range map[string]string{
		"empty":       "\n",
		"private":     "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"unsupported": "ssh-dss AAAA synthetic\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(keyPath, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSSHPublicKey(keyPath); err == nil || strings.Contains(err.Error(), keyPath) {
				t.Fatalf("invalid key error = %v", err)
			}
		})
	}
	if _, err := readSSHPublicKey(filepath.Join(t.TempDir(), "missing.pub")); err == nil || strings.Contains(err.Error(), "missing.pub") {
		t.Fatalf("missing key error = %v", err)
	}
}

func TestSatelliteReusePersistsOwnershipWithoutPublicKey(t *testing.T) {
	workspace := t.TempDir()
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredSatelliteInputs(t)
	inputs.SatelliteManagedFrom = ""
	inputs.SatelliteLocationID = " location-existing "
	inputs.SatelliteSSHPublicKeyPath = ""
	inputs.SatelliteSSHKeyID = " key-existing "
	inputs.VPCID = " vpc-existing "
	inputs.SubnetIDs = []string{"subnet-3", "subnet-1", "subnet-2"}
	inputs.PublicGatewayIDs = []string{"gateway-2", "gateway-3", "gateway-1"}

	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ictterraform.TFVarsName, ictterraform.ContextName} {
		contents, err := os.ReadFile(filepath.Join(workspace, path))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"vpc-existing", "subnet-1", "gateway-1", "location-existing", "key-existing"} {
			if !strings.Contains(string(contents), id) {
				t.Fatalf("%s does not persist %s", path, id)
			}
		}
		if strings.Contains(string(contents), "ssh-ed25519") {
			t.Fatalf("%s contains SSH public-key material", path)
		}
	}
	writeTerraformState(t, workspace)
	fake.resources = true
	changed := inputs
	changed.SatelliteLocationID = "location-other"
	fake.calls = nil
	if err := runner.Create(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
		t.Fatalf("changed Satellite location create error = %v", err)
	}
	if err := runner.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSatelliteWorkerReuseValidationPersistenceAndRecovery(t *testing.T) {
	for name, test := range map[string]struct {
		mutate func(*Inputs)
		want   string
	}{
		"requires location":           {mutate: func(in *Inputs) { in.SatelliteLocationID = "" }, want: "requires satellite-location-id"},
		"requires worker cardinality": {mutate: func(in *Inputs) { in.WorkerCount, in.SatelliteWorkerInstanceIDs = 3, []string{"worker-1"} }, want: "exactly 3"},
		"rejects duplicates":          {mutate: func(in *Inputs) { in.SatelliteWorkerInstanceIDs = []string{"worker-1", "worker-1"} }, want: "duplicate satellite-worker-instance-id"},
		"rejects unused networking":   {mutate: func(in *Inputs) { in.VPCID = "vpc-existing" }, want: "networking inputs"},
		"rejects unused SSH key":      {mutate: func(in *Inputs) { in.SatelliteSSHKeyID = "key-existing" }, want: "SSH key inputs"},
		"rejects other providers": {mutate: func(in *Inputs) {
			in.Provider = "vpc-gen2"
			in.Platform, in.Version, in.Zone, in.Flavor, in.Name = "kubernetes", "1.31", "us-south-1", "bx2.2x8", "fixture-cluster"
		}, want: "only supported by the satellite provider"},
	} {
		t.Run(name, func(t *testing.T) {
			inputs := configuredSatelliteInputs(t)
			inputs.SatelliteManagedFrom, inputs.SatelliteHostImage, inputs.SatelliteSSHPublicKeyPath = "", "", ""
			inputs.SatelliteLocationID = "location-existing"
			inputs.SatelliteWorkerInstanceIDs = []string{"worker-1"}
			test.mutate(&inputs)
			cfg, err := config.Load(inputs.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := newRunner(t.TempDir(), &fakeTerraform{}).resolve(context.Background(), cfg, inputs); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Satellite worker reuse validation error = %v, want %q", err, test.want)
			}
		})
	}

	workspace := t.TempDir()
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredSatelliteInputs(t)
	inputs.SatelliteManagedFrom, inputs.SatelliteHostImage, inputs.SatelliteSSHPublicKeyPath = "", "", ""
	inputs.SatelliteLocationID = " location-existing "
	inputs.SatelliteWorkerInstanceIDs = []string{" worker-1 "}
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ictterraform.TFVarsName, ictterraform.ContextName} {
		contents, err := os.ReadFile(filepath.Join(workspace, path))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(contents), "worker-1") || strings.Contains(string(contents), "satellite_host_image") || strings.Contains(string(contents), "ssh-ed25519") {
			t.Fatalf("%s does not persist only reused-worker ownership: %s", path, contents)
		}
	}
	writeTerraformState(t, workspace)
	fake.resources = true
	changed := inputs
	changed.SatelliteWorkerInstanceIDs = []string{"worker-other"}
	fake.calls = nil
	if err := runner.Create(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
		t.Fatalf("changed Satellite worker create error = %v", err)
	}
	if got := strings.Join(terraformActions(t, fake.calls), ", "); got != "init, state list" {
		t.Fatalf("changed Satellite worker actions = %q", got)
	}
	if err := runner.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSatelliteTerraformTopology(t *testing.T) {
	asset, err := os.ReadFile(filepath.Join("..", "terraform", "assets", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	contents := string(asset)
	for _, required := range []string{
		"ibm_is_instance\" \"satellite_control_plane\"",
		"count = var.cluster_mode == \"satellite\" && var.satellite_location_id == null ? 3 : 0",
		"data \"ibm_satellite_location\" \"satellite\"",
		"data \"ibm_is_ssh_key\" \"satellite\"",
		"effective_satellite_subnet_id_by_zone",
		"effective_satellite_gateway_id_by_zone",
		"data \"ibm_is_instances\" \"satellite_worker\"",
		"satellite_worker_instance_ids",
		"ibm_is_instance\" \"satellite_worker\"",
		"count = local.satellite_managed_infrastructure_needed ? var.worker_count : 0",
		"satellite-role:control-plane",
		"satellite-role:cluster-worker",
		"worker_pool   = \"default\"",
	} {
		if !strings.Contains(contents, required) {
			t.Fatalf("Satellite Terraform topology is missing %q", required)
		}
	}
	for _, forbidden := range []string{"ibm_cos_", "ibm_kms_"} {
		if strings.Contains(contents, forbidden) {
			t.Fatalf("Satellite Terraform topology contains %s", forbidden)
		}
	}
}
