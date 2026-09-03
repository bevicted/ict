package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bevicted/ict/internal/config"
	"github.com/bevicted/ict/internal/prompt"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

type fakeTerraform struct {
	resources bool
	initErr   error
	stateErr  error
	calls     [][]string
	environs  [][]string
}

type fakeIBMCloud struct {
	calls    [][]string
	environs [][]string
}

func (f *fakeIBMCloud) Run(_ context.Context, environ []string, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	f.environs = append(f.environs, append([]string(nil), environ...))
	switch args[0] {
	case "resource":
		return []byte(`[{"name":"fixture-group"}]`), nil
	case "ks":
		switch args[1] {
		case "zones":
			for _, arg := range args {
				switch arg {
				case "classic":
					return []byte(`[{"name":"dal10"}]`), nil
				case "satellite":
					return []byte(`[{"name":"us-south"}]`), nil
				}
			}
			return []byte(`[{"name":"us-south-1"},{"name":"us-south-2"},{"name":"us-south-3"}]`), nil
		case "versions":
			return []byte(`{"kubernetes":[{"major":1,"minor":31,"patch":9}],"openshift":[{"major":4,"minor":17,"patch":3}]}`), nil
		case "flavor":
			return []byte(`[{"name":"bx2.2x8"}]`), nil
		}
	case "is":
		switch args[1] {
		case "images":
			return []byte(`[{"name":"rhel-8-synthetic"}]`), nil
		case "instance-profiles":
			return []byte(`[{"name":"bx2-4x16"}]`), nil
		}
	}
	return nil, errors.New("unexpected discovery command")
}

func (f *fakeTerraform) Run(_ context.Context, environ []string, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	f.environs = append(f.environs, append([]string(nil), environ...))
	if len(args) >= 2 && args[1] == "init" && f.initErr != nil {
		return nil, f.initErr
	}
	if len(args) >= 2 && args[len(args)-2] == "state" && args[len(args)-1] == "list" {
		if f.stateErr != nil {
			return nil, f.stateErr
		}
		if f.resources {
			return []byte("ibm_container_vpc_cluster.cluster\n"), nil
		}
		return nil, nil
	}
	return nil, nil
}

const testConfig = `version: 1
targets:
  example:
    providers: [vpc-gen2, classic]
    default_region: us-south
    endpoints:
      iam: https://iam.example.invalid
      container_service: https://containers.example.invalid
      global_tagging: https://tagging.example.invalid
      resource_management: https://management.example.invalid
      resource_controller: https://controller.example.invalid
      vpc: https://vpc.{region}.example.invalid
`

func configuredInputs(t *testing.T) Inputs {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return Inputs{ConfigPath: path, Target: "example", Provider: "vpc-gen2", Platform: "kubernetes", Version: "1.31.9", ResourceGroup: "fixture-group", Zone: "us-south-1", Flavor: "bx2.2x8", Name: "fixture-cluster"}
}

func publicKeyLine() string {
	keyType := "ssh-ed25519"
	encoded := make([]byte, 4+len(keyType)+4+32)
	binary.BigEndian.PutUint32(encoded[:4], uint32(len(keyType)))
	copy(encoded[4:], keyType)
	binary.BigEndian.PutUint32(encoded[4+len(keyType):], 32)
	return keyType + " " + base64.StdEncoding.EncodeToString(encoded) + " synthetic-comment"
}

func configuredSatelliteInputs(t *testing.T) Inputs {
	t.Helper()
	inputs := configuredInputs(t)
	content, err := os.ReadFile(inputs.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), "[vpc-gen2, classic]", "[vpc-gen2, classic, satellite]", 1))
	content = []byte(strings.Replace(string(content), "      vpc: https://vpc.{region}.example.invalid\n", "      vpc: https://vpc.{region}.example.invalid\n      satellite: https://satellite.example.invalid\n      satellite_config: https://satellite-config.example.invalid\n", 1))
	if err := os.WriteFile(inputs.ConfigPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "satellite.pub")
	if err := os.WriteFile(keyPath, []byte("\n"+publicKeyLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs.Provider = "satellite"
	inputs.Platform = "openshift"
	inputs.Version = "4.17.3"
	inputs.Zone, inputs.Flavor = "", ""
	inputs.Name = "fixture-satellite"
	inputs.SatelliteZones = []string{"us-south-1", "us-south-2", "us-south-3"}
	inputs.SatelliteManagedFrom = "us-south"
	inputs.SatelliteHostImage = "rhel-8-synthetic"
	inputs.SatelliteSSHPublicKeyPath = keyPath
	return inputs
}

func configuredClassicInputs(t *testing.T) Inputs {
	inputs := configuredInputs(t)
	inputs.Provider = "classic"
	inputs.Platform = "openshift"
	inputs.Zone, inputs.Flavor = "", ""
	inputs.Datacenter = "dal10"
	inputs.MachineType = "bx2.2x8"
	inputs.PublicVLANID = "12345"
	inputs.PrivateVLANID = "67890"
	return inputs
}

func newRunner(workspace string, fake *fakeTerraform) Runner {
	return Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }, Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }, Suffix: func() string { return "deadbeef" }}
}

func writeTerraformState(t *testing.T, workspace string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(workspace, "terraform.tfstate"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func terraformActions(t *testing.T, calls [][]string) []string {
	t.Helper()
	actions := make([]string, 0, len(calls))
	for _, call := range calls {
		switch {
		case len(call) >= 2 && call[1] == "init":
			actions = append(actions, "init")
		case len(call) >= 3 && call[1] == "state" && call[2] == "list":
			actions = append(actions, "state list")
		case len(call) >= 2 && call[1] == "plan":
			actions = append(actions, "plan")
		case len(call) >= 2 && call[1] == "apply":
			actions = append(actions, "apply")
		case len(call) >= 2 && call[1] == "destroy":
			actions = append(actions, "destroy")
		default:
			t.Fatalf("unexpected Terraform call: %#v", call)
		}
	}
	return actions
}

func TestInitialLifecycleTerraformActionOrder(t *testing.T) {
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
	}{
		{name: "VPC", inputs: configuredInputs},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}},
		{name: "Satellite", inputs: configuredSatelliteInputs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, action := range []string{"plan", "create"} {
				t.Run(action, func(t *testing.T) {
					fake := &fakeTerraform{}
					runner := newRunner(t.TempDir(), fake)
					runner.Environ = test.environ

					var err error
					if action == "plan" {
						err = runner.Plan(context.Background(), test.inputs(t))
					} else {
						err = runner.Create(context.Background(), test.inputs(t))
					}
					if err != nil {
						t.Fatal(err)
					}
					want := "init, " + action
					if action == "create" {
						want = "init, apply"
					}
					if got := strings.Join(terraformActions(t, fake.calls), ", "); got != want {
						t.Fatalf("%s first-run Terraform actions = %q, want %q", action, got, want)
					}
				})
			}
		})
	}
}

func TestHasState(t *testing.T) {
	tests := []struct {
		name      string
		stateFile bool
		resources bool
		stateErr  error
		want      bool
		wantErr   string
		calls     int
	}{
		{name: "absent state", want: false},
		{name: "existing empty state", stateFile: true, want: false, calls: 1},
		{name: "existing non-empty state", stateFile: true, resources: true, want: true, calls: 1},
		{name: "existing state-list error", stateFile: true, stateErr: errors.New("state unavailable"), wantErr: "state unavailable", calls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			if test.stateFile {
				writeTerraformState(t, workspace)
			}
			fake := &fakeTerraform{resources: test.resources, stateErr: test.stateErr}
			runner := newRunner(workspace, fake)

			got, err := runner.hasState(context.Background(), nil, workspace)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("hasState error = %v, want %q", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("hasState = %t, want %t", got, test.want)
			}
			if len(fake.calls) != test.calls {
				t.Fatalf("state-list calls = %#v, want %d", fake.calls, test.calls)
			}
		})
	}
}

func TestLifecyclePersistsAndGuardsState(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "state", "ict", "terraform")
	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(workspace, fake)
	runner.IBMCloud = discovery
	runner.Environ = []string{
		"IBMCLOUD_CS_API_ENDPOINT=https://override-containers.example.invalid",
		"IBMCLOUD_IS_NG_API_ENDPOINT=https://override-vpc.example.invalid",
	}
	inputs := configuredInputs(t)
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if len(discovery.environs) != 0 {
		t.Fatalf("fully specified inputs triggered discovery: %d calls", len(discovery.environs))
	}
	for _, environ := range fake.environs {
		for key, want := range map[string]string{
			"IBMCLOUD_CS_API_ENDPOINT":    "https://override-containers.example.invalid",
			"IBMCLOUD_IS_NG_API_ENDPOINT": "https://override-vpc.example.invalid",
		} {
			if got := environmentValue(environ, key); got != want {
				t.Fatalf("Terraform %s = %q, want %q", key, got, want)
			}
		}
	}
	for _, path := range []string{filepath.Join(workspace, "main.tf"), filepath.Join(workspace, "cluster-name.tftest.hcl"), filepath.Join(workspace, "satellite-topology.tftest.hcl"), filepath.Join(workspace, ictterraform.TFVarsName), filepath.Join(workspace, ictterraform.ContextName)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private runtime file %s = %v, %v", path, info, err)
		}
	}
	contextBytes, err := os.ReadFile(filepath.Join(workspace, ictterraform.ContextName))
	if err != nil || !strings.Contains(string(contextBytes), "override-vpc.example.invalid") {
		t.Fatalf("recovery context = %q, %v", contextBytes, err)
	}
	writeTerraformState(t, workspace)
	fake.resources = true
	fake.calls = nil
	if err := runner.Create(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.calls[len(fake.calls)-1], " "); !strings.Contains(got, "apply -input=false -auto-approve") {
		t.Fatalf("create did not apply: %q", got)
	}
	changed := inputs
	changed.Name = "other-cluster"
	fake.calls = nil
	err = runner.Create(context.Background(), changed)
	if err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
		t.Fatalf("mismatched create error = %v", err)
	}
	if got := strings.Join(terraformActions(t, fake.calls), ", "); got != "init, state list" {
		t.Fatalf("mismatched create actions = %q", got)
	}
	fake.calls = nil
	if err := runner.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.calls[len(fake.calls)-1], " "); !strings.Contains(got, "destroy -input=false -auto-approve") {
		t.Fatalf("destroy did not run: %q", got)
	}
}

func TestClassicLifecyclePersistsAndOmitsVPCValues(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "state", "ict", "terraform")
	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(workspace, fake)
	runner.IBMCloud = discovery
	runner.Environ = []string{
		"IAAS_CLASSIC_USERNAME=synthetic-user",
		"IAAS_CLASSIC_API_KEY=synthetic-api-key",
		"IBMCLOUD_CS_API_ENDPOINT=https://override-containers.example.invalid",
	}
	inputs := configuredClassicInputs(t)
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if len(discovery.environs) != 0 {
		t.Fatalf("fully specified Classic inputs triggered discovery: %d calls", len(discovery.environs))
	}
	tfvars, err := os.ReadFile(filepath.Join(workspace, ictterraform.TFVarsName))
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"\"zone\"", "\"flavor\""} {
		if strings.Contains(string(tfvars), absent) {
			t.Fatalf("Classic tfvars contains VPC-only field %s", absent)
		}
	}
	for _, present := range []string{"\"datacenter\":\"dal10\"", "\"machine_type\":\"bx2.2x8\"", "\"public_vlan_id\":\"12345\"", "\"private_vlan_id\":\"67890\"", "\"worker_count\":3"} {
		if !strings.Contains(string(tfvars), present) {
			t.Fatalf("Classic tfvars missing %s", present)
		}
	}
	writeTerraformState(t, workspace)
	fake.resources = true
	fake.calls = nil
	if err := runner.Create(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.calls[len(fake.calls)-1], " "); !strings.Contains(got, "apply -input=false -auto-approve") {
		t.Fatalf("Classic create did not apply: %q", got)
	}
	changed := inputs
	changed.Datacenter = "wdc04"
	fake.calls = nil
	if err := runner.Create(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
		t.Fatalf("mismatched Classic create error = %v", err)
	}
	if got := strings.Join(terraformActions(t, fake.calls), ", "); got != "init, state list" {
		t.Fatalf("mismatched Classic create actions = %q", got)
	}
	fake.calls = nil
	if err := runner.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.calls[len(fake.calls)-1], " "); !strings.Contains(got, "destroy -input=false -auto-approve") {
		t.Fatalf("Classic destroy did not run: %q", got)
	}
}

func TestClassicValidationAndCredentialPreflight(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Inputs)
		environ []string
		want    string
	}{
		"missing VLAN": {
			mutate: func(in *Inputs) { in.PublicVLANID = "" },
			want:   "missing required input(s): public-vlan-id",
		},
		"non-numeric VLAN": {
			mutate: func(in *Inputs) { in.PrivateVLANID = "not-numeric" },
			want:   "private VLAN ID must be a numeric",
		},
		"missing credentials": {
			environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user"},
			want:    "IAAS_CLASSIC_API_KEY",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fake := &fakeTerraform{}
			runner := newRunner(t.TempDir(), fake)
			runner.Environ = test.environ
			inputs := configuredClassicInputs(t)
			if test.mutate != nil {
				test.mutate(&inputs)
			}
			err := runner.Plan(context.Background(), inputs)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Classic preflight error = %v, want %q", err, test.want)
			}
			if strings.Contains(err.Error(), "synthetic-user") {
				t.Fatalf("credential value appeared in error: %q", err)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("Classic preflight called Terraform: %#v", fake.calls)
			}
		})
	}
}

func TestClassicDiscoveryAndMissingInputBehavior(t *testing.T) {
	bin := t.TempDir()
	fzf := filepath.Join(bin, "fzf")
	if err := os.WriteFile(fzf, []byte("#!/bin/sh\nIFS= read -r value\nprintf '%s\\n' \"$value\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(t.TempDir(), fake)
	runner.Terminal = func() bool { return true }
	runner.IBMCloud = discovery
	runner.Environ = []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}
	inputs := configuredClassicInputs(t)
	inputs.Datacenter, inputs.MachineType = "", ""
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if len(discovery.environs) == 0 {
		t.Fatal("omitted Classic discovery inputs did not invoke ibmcloud")
	}

	fake.calls = nil
	discovery.environs = nil
	runner.Terminal = func() bool { return false }
	inputs.Datacenter = ""
	err := runner.Plan(context.Background(), inputs)
	var missing *prompt.MissingInputError
	if err == nil || !errors.As(err, &missing) || !strings.Contains(err.Error(), "datacenter") {
		t.Fatalf("non-interactive Classic missing input error = %v", err)
	}
	if len(discovery.environs) != 0 || len(fake.calls) != 0 {
		t.Fatalf("non-interactive Classic missing input invoked discovery or Terraform: discovery=%d terraform=%d", len(discovery.environs), len(fake.calls))
	}
}

func TestClassicTerraformUsesExistingVLANInputs(t *testing.T) {
	asset, err := os.ReadFile(filepath.Join("..", "terraform", "assets", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	contents := string(asset)
	if !strings.Contains(contents, "resource \"ibm_container_cluster\" \"cluster\"") {
		t.Fatal("Terraform asset does not define the Classic cluster resource")
	}
	if strings.Contains(contents, "resource \"ibm_network_vlan\"") {
		t.Fatal("Terraform asset manages a Classic VLAN")
	}
	for _, input := range []string{"public_vlan_id", "private_vlan_id"} {
		if !strings.Contains(contents, "var."+input) {
			t.Fatalf("Terraform asset does not pass existing %s", input)
		}
	}
}

func TestClassicTargetIsRejectedBeforeDiscovery(t *testing.T) {
	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(t.TempDir(), fake)
	runner.Terminal = func() bool { return true }
	runner.IBMCloud = discovery
	inputs := configuredClassicInputs(t)
	content, err := os.ReadFile(inputs.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputs.ConfigPath, []byte(strings.Replace(string(content), "[vpc-gen2, classic]", "[vpc-gen2]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runner.Plan(context.Background(), inputs)
	if err == nil || !strings.Contains(err.Error(), "does not support provider") {
		t.Fatalf("unsupported Classic target error = %v", err)
	}
	if len(discovery.environs) != 0 || len(fake.calls) != 0 {
		t.Fatalf("unsupported Classic target invoked discovery or Terraform: discovery=%d terraform=%d", len(discovery.environs), len(fake.calls))
	}
}

func TestClassicWorkerDefaultsAndExplicitOverride(t *testing.T) {
	for name, test := range map[string]struct {
		platform string
		workers  int
		want     int
	}{
		"Kubernetes default":         {platform: "kubernetes", want: 1},
		"OpenShift default":          {platform: "openshift", want: 3},
		"explicit positive override": {platform: "openshift", workers: 2, want: 2},
	} {
		t.Run(name, func(t *testing.T) {
			inputs := configuredClassicInputs(t)
			inputs.Platform = test.platform
			inputs.WorkerCount = test.workers
			cfg, err := config.Load(inputs.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			values, _, err := newRunner(t.TempDir(), &fakeTerraform{}).resolve(context.Background(), cfg, inputs)
			if err != nil || values.WorkerCount != test.want {
				t.Fatalf("Classic workers = %d, %v, want %d", values.WorkerCount, err, test.want)
			}
		})
	}
}

func TestClassicRejectsNonpositiveWorkerOverride(t *testing.T) {
	inputs := configuredClassicInputs(t)
	inputs.WorkerCount = -1
	cfg, err := config.Load(inputs.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = newRunner(t.TempDir(), &fakeTerraform{}).resolve(context.Background(), cfg, inputs)
	if err == nil || !strings.Contains(err.Error(), "worker count must be at least one") {
		t.Fatalf("Classic nonpositive worker count error = %v", err)
	}
}

func TestDestroyRefusesEmptyState(t *testing.T) {
	workspace := t.TempDir()
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "no saved context") {
		t.Fatalf("destroy without context = %v", err)
	}
	if err := runner.Plan(context.Background(), configuredInputs(t)); err != nil {
		t.Fatal(err)
	}
	writeTerraformState(t, workspace)
	fake.calls = nil
	if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "state has no managed resources") {
		t.Fatalf("empty state destroy = %v", err)
	}
	if len(fake.calls) != 1 || !strings.HasSuffix(strings.Join(fake.calls[0], " "), "state list") {
		t.Fatalf("empty state destroy calls = %#v", fake.calls)
	}
}

func TestDestroyRequiresCompleteSavedContext(t *testing.T) {
	endpointFields := []struct {
		name        string
		environment string
		clear       func(*config.Endpoints)
	}{
		{name: "iam", environment: "IBMCLOUD_IAM_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.IAM = "" }},
		{name: "container service", environment: "IBMCLOUD_CS_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.ContainerService = "" }},
		{name: "global tagging", environment: "IBMCLOUD_GT_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.GlobalTagging = "" }},
		{name: "resource management", environment: "IBMCLOUD_RESOURCE_MANAGEMENT_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.ResourceManagement = "" }},
		{name: "resource controller", environment: "IBMCLOUD_RESOURCE_CONTROLLER_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.ResourceController = "" }},
	}
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
		fields  []struct {
			name        string
			environment string
			clear       func(*config.Endpoints)
		}
	}{
		{name: "VPC", inputs: configuredInputs, fields: append(endpointFields, struct {
			name        string
			environment string
			clear       func(*config.Endpoints)
		}{name: "VPC", environment: "IBMCLOUD_IS_NG_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.VPC = "" }})},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}, fields: endpointFields},
		{name: "Satellite", inputs: configuredSatelliteInputs, fields: append(endpointFields,
			struct {
				name        string
				environment string
				clear       func(*config.Endpoints)
			}{name: "VPC", environment: "IBMCLOUD_IS_NG_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.VPC = "" }},
			struct {
				name        string
				environment string
				clear       func(*config.Endpoints)
			}{name: "Satellite", environment: "IBMCLOUD_SATELLITE_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.Satellite = "" }},
			struct {
				name        string
				environment string
				clear       func(*config.Endpoints)
			}{name: "Satellite config", environment: "IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT", clear: func(endpoints *config.Endpoints) { endpoints.SatelliteConfig = "" }},
		)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, field := range test.fields {
				t.Run(field.name, func(t *testing.T) {
					workspace := t.TempDir()
					fake := &fakeTerraform{}
					runner := newRunner(workspace, fake)
					runner.Environ = test.environ
					if err := runner.Plan(context.Background(), test.inputs(t)); err != nil {
						t.Fatal(err)
					}
					contextPath := filepath.Join(workspace, ictterraform.ContextName)
					data, err := os.ReadFile(contextPath)
					if err != nil {
						t.Fatal(err)
					}
					var recovery RecoveryContext
					if err := json.Unmarshal(data, &recovery); err != nil {
						t.Fatal(err)
					}
					field.clear(&recovery.Endpoints)
					data, err = json.Marshal(recovery)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(contextPath, data, 0o600); err != nil {
						t.Fatal(err)
					}
					runner.Environ = append(append([]string(nil), test.environ...), field.environment+"=https://current.example.invalid")
					fake.resources = true
					fake.calls = nil
					if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "incomplete or invalid saved context") {
						t.Fatalf("destroy with incomplete context = %v", err)
					}
					if len(fake.calls) != 0 {
						t.Fatalf("destroy with incomplete context called Terraform: %#v", fake.calls)
					}
				})
			}
		})
	}
}

func TestDestroyRejectsPartialOrMismatchedSavedValues(t *testing.T) {
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
		partial func(*Values)
	}{
		{name: "VPC", inputs: configuredInputs, partial: func(values *Values) { values.Zone = "" }},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}, partial: func(values *Values) { values.Datacenter = "" }},
		{name: "Satellite", inputs: configuredSatelliteInputs, partial: func(values *Values) { values.SatelliteHostProfile = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, scenario := range []struct {
				name   string
				path   string
				mutate func(*Values)
			}{
				{name: "partial recovery values", path: ictterraform.ContextName, mutate: test.partial},
				{name: "tfvars mismatch", path: ictterraform.TFVarsName, mutate: func(values *Values) { values.ClusterName += "-other" }},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					workspace := t.TempDir()
					fake := &fakeTerraform{}
					runner := newRunner(workspace, fake)
					runner.Environ = test.environ
					if err := runner.Plan(context.Background(), test.inputs(t)); err != nil {
						t.Fatal(err)
					}

					contextPath := filepath.Join(workspace, ictterraform.ContextName)
					tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
					contextBytes, err := os.ReadFile(contextPath)
					if err != nil {
						t.Fatal(err)
					}
					var recovery RecoveryContext
					if err := json.Unmarshal(contextBytes, &recovery); err != nil {
						t.Fatal(err)
					}
					tfvarsBytes, err := os.ReadFile(tfvarsPath)
					if err != nil {
						t.Fatal(err)
					}
					var values Values
					if err := json.Unmarshal(tfvarsBytes, &values); err != nil {
						t.Fatal(err)
					}
					if scenario.path == ictterraform.ContextName {
						scenario.mutate(&recovery.Values)
						contextBytes, err = json.Marshal(recovery)
						if err == nil {
							err = os.WriteFile(contextPath, contextBytes, 0o600)
						}
					} else {
						scenario.mutate(&values)
						tfvarsBytes, err = json.Marshal(values)
						if err == nil {
							err = os.WriteFile(tfvarsPath, tfvarsBytes, 0o600)
						}
					}
					if err != nil {
						t.Fatal(err)
					}

					fake.resources = true
					fake.calls = nil
					if err := runner.Destroy(context.Background()); err == nil {
						t.Fatal("destroy accepted invalid saved values")
					}
					if len(fake.calls) != 0 {
						t.Fatalf("destroy with invalid saved values called Terraform: %#v", fake.calls)
					}
				})
			}
		})
	}
}

func TestRecoveryContextAtomicallyBindsExactTFVars(t *testing.T) {
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
	}{
		{name: "VPC", inputs: configuredInputs},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}},
		{name: "Satellite", inputs: configuredSatelliteInputs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			fake := &fakeTerraform{}
			runner := newRunner(workspace, fake)
			runner.Environ = test.environ
			if err := runner.Plan(context.Background(), test.inputs(t)); err != nil {
				t.Fatal(err)
			}

			tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
			contextPath := filepath.Join(workspace, ictterraform.ContextName)
			tfvars, err := os.ReadFile(tfvarsPath)
			if err != nil {
				t.Fatal(err)
			}
			contextData, err := os.ReadFile(contextPath)
			if err != nil {
				t.Fatal(err)
			}
			var recovery RecoveryContext
			if err := json.Unmarshal(contextData, &recovery); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(tfvars)
			if got, want := recovery.TFVarsSHA256, hex.EncodeToString(digest[:]); got != want {
				t.Fatalf("saved tfvars digest = %q, want digest of persisted tfvars", got)
			}
			if _, err := readRecovery(contextPath); err != nil {
				t.Fatalf("persisted recovery context did not round trip: %v", err)
			}
			for _, path := range []string{tfvarsPath, contextPath} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("private runtime file %s = %v, %v", path, info, err)
				}
			}
			if temporary, err := filepath.Glob(filepath.Join(workspace, ".cluster", ".ict-*")); err != nil || len(temporary) != 0 {
				t.Fatalf("atomic persistence left temporary files: %v, %v", temporary, err)
			}

			if err := os.WriteFile(tfvarsPath, append(tfvars, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			fake.resources = true
			fake.calls = nil
			if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "requested inputs differ") {
				t.Fatalf("destroy after tfvars byte change = %v", err)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("destroy after tfvars byte change called Terraform: %#v", fake.calls)
			}
		})
	}
}

func TestDestroyRestoresSavedEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		inputs     func(*testing.T) Inputs
		savedEnv   []string
		currentEnv []string
		key        string
		want       string
	}{
		{name: "VPC", inputs: configuredInputs, savedEnv: []string{"IBMCLOUD_IS_NG_API_ENDPOINT=https://saved-vpc.example.invalid"}, currentEnv: []string{"IBMCLOUD_IS_NG_API_ENDPOINT=https://current-vpc.example.invalid"}, key: "IBMCLOUD_IS_NG_API_ENDPOINT", want: "https://saved-vpc.example.invalid"},
		{name: "Classic", inputs: configuredClassicInputs, savedEnv: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key", "IBMCLOUD_CS_API_ENDPOINT=https://saved-container.example.invalid"}, currentEnv: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key", "IBMCLOUD_CS_API_ENDPOINT=https://current-container.example.invalid"}, key: "IBMCLOUD_CS_API_ENDPOINT", want: "https://saved-container.example.invalid"},
		{name: "Satellite", inputs: configuredSatelliteInputs, savedEnv: []string{"IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT=https://saved-satellite-config.example.invalid"}, currentEnv: []string{"IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT=https://current-satellite-config.example.invalid"}, key: "IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT", want: "https://saved-satellite-config.example.invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeTerraform{}
			runner := newRunner(t.TempDir(), fake)
			runner.Environ = test.savedEnv
			if err := runner.Plan(context.Background(), test.inputs(t)); err != nil {
				t.Fatal(err)
			}
			writeTerraformState(t, runner.Workspace)
			fake.resources = true
			fake.calls, fake.environs = nil, nil
			runner.Environ = test.currentEnv
			if err := runner.Destroy(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, environ := range fake.environs {
				if got := environmentValue(environ, test.key); got != test.want {
					t.Fatalf("destroy %s = %q, want saved %q", test.key, got, test.want)
				}
			}
		})
	}
}

func TestStateListFailuresRefusePlanAndCreateBeforePersistence(t *testing.T) {
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
	}{
		{name: "VPC", inputs: configuredInputs},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}},
		{name: "Satellite", inputs: configuredSatelliteInputs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, action := range []string{"plan", "create"} {
				t.Run(action, func(t *testing.T) {
					workspace := t.TempDir()
					writeTerraformState(t, workspace)
					fake := &fakeTerraform{stateErr: errors.New("state unavailable")}
					runner := newRunner(workspace, fake)
					runner.Environ = test.environ

					var err error
					if action == "plan" {
						err = runner.Plan(context.Background(), test.inputs(t))
					} else {
						err = runner.Create(context.Background(), test.inputs(t))
					}
					if err == nil || !strings.Contains(err.Error(), "inspect Terraform state: state unavailable") {
						t.Fatalf("%s state-list error = %v", action, err)
					}
					if got := strings.Join(terraformActions(t, fake.calls), ", "); got != "init, state list" {
						t.Fatalf("%s state-list error actions = %q", action, got)
					}
					for _, path := range []string{ictterraform.TFVarsName, ictterraform.ContextName} {
						if _, err := os.Stat(filepath.Join(workspace, path)); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("%s persisted after state-list error: %v", path, err)
						}
					}
				})
			}
		})
	}
}

func TestInitFailuresRefusePlanAndCreateBeforePersistence(t *testing.T) {
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
	}{
		{name: "VPC", inputs: configuredInputs},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}},
		{name: "Satellite", inputs: configuredSatelliteInputs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, action := range []string{"plan", "create"} {
				t.Run(action, func(t *testing.T) {
					workspace := t.TempDir()
					fake := &fakeTerraform{initErr: errors.New("initialization unavailable")}
					runner := newRunner(workspace, fake)
					runner.Environ = test.environ

					var err error
					if action == "plan" {
						err = runner.Plan(context.Background(), test.inputs(t))
					} else {
						err = runner.Create(context.Background(), test.inputs(t))
					}
					if err == nil || !strings.Contains(err.Error(), "initialization unavailable") {
						t.Fatalf("%s init error = %v", action, err)
					}
					if got := strings.Join(terraformActions(t, fake.calls), ", "); got != "init" {
						t.Fatalf("%s init error actions = %q", action, got)
					}
					for _, path := range []string{ictterraform.TFVarsName, ictterraform.ContextName} {
						if _, err := os.Stat(filepath.Join(workspace, path)); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("%s persisted after init error: %v", path, err)
						}
					}
				})
			}
		})
	}
}

func TestStateListFailuresRefuseDestroy(t *testing.T) {
	tests := []struct {
		name    string
		inputs  func(*testing.T) Inputs
		environ []string
	}{
		{name: "VPC", inputs: configuredInputs},
		{name: "Classic", inputs: configuredClassicInputs, environ: []string{"IAAS_CLASSIC_USERNAME=synthetic-user", "IAAS_CLASSIC_API_KEY=synthetic-api-key"}},
		{name: "Satellite", inputs: configuredSatelliteInputs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			fake := &fakeTerraform{}
			runner := newRunner(workspace, fake)
			runner.Environ = test.environ
			if err := runner.Plan(context.Background(), test.inputs(t)); err != nil {
				t.Fatal(err)
			}
			writeTerraformState(t, workspace)
			fake.stateErr = errors.New("state unavailable")
			fake.calls = nil
			if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "inspect Terraform state: state unavailable") {
				t.Fatalf("destroy state-list error = %v", err)
			}
			if len(fake.calls) != 1 || !strings.HasSuffix(strings.Join(fake.calls[0], " "), "state list") {
				t.Fatalf("destroy calls = %#v", fake.calls)
			}
		})
	}
}

func TestMissingInputsDoNotDiscoverWithoutTerminal(t *testing.T) {
	workspace := t.TempDir()
	runner := newRunner(workspace, &fakeTerraform{})
	inputs := configuredInputs(t)
	inputs.Zone = ""
	err := runner.Plan(context.Background(), inputs)
	var missing *prompt.MissingInputError
	if err == nil || !errors.As(err, &missing) || !strings.Contains(err.Error(), "missing required input(s): zone") {
		t.Fatalf("missing input error = %v", err)
	}
}

func TestTerminalDiscoveryUsesFzfOnlyForMissingInputs(t *testing.T) {
	bin := t.TempDir()
	fzf := filepath.Join(bin, "fzf")
	if err := os.WriteFile(fzf, []byte("#!/bin/sh\nIFS= read -r value\nprintf '%s\\n' \"$value\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	workspace := filepath.Join(t.TempDir(), "workspace")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	runner.Terminal = func() bool { return true }
	runner.IBMCloud = &fakeIBMCloud{}
	runner.Environ = []string{"USER=fixture-user"}
	inputs := configuredInputs(t)
	inputs.Platform, inputs.Version, inputs.ResourceGroup, inputs.Zone, inputs.Flavor = "", "", "", "", ""
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) == 0 {
		t.Fatal("discovered plan did not invoke Terraform")
	}
}

func TestDiscoveryScopesValidatedEndpointOverrides(t *testing.T) {
	bin := t.TempDir()
	fzf := filepath.Join(bin, "fzf")
	if err := os.WriteFile(fzf, []byte("#!/bin/sh\nIFS= read -r value\nprintf '%s\\n' \"$value\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	fake := &fakeTerraform{}
	discovery := &fakeIBMCloud{}
	runner := newRunner(t.TempDir(), fake)
	runner.Terminal = func() bool { return true }
	runner.IBMCloud = discovery
	runner.Environ = []string{
		"IBMCLOUD_CS_API_ENDPOINT=https://override-containers.example.invalid",
		"IBMCLOUD_IS_NG_API_ENDPOINT=https://override-vpc.example.invalid",
	}
	inputs := configuredInputs(t)
	inputs.Zone = ""
	if err := runner.Plan(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if len(discovery.environs) != 1 {
		t.Fatalf("discovery calls = %d", len(discovery.environs))
	}
	for key, want := range map[string]string{
		"IBMCLOUD_CS_API_ENDPOINT":    "https://override-containers.example.invalid",
		"IBMCLOUD_IS_NG_API_ENDPOINT": "https://override-vpc.example.invalid",
	} {
		if got := environmentValue(discovery.environs[0], key); got != want {
			t.Fatalf("discovery %s = %q, want %q", key, got, want)
		}
	}

	runner.Environ = []string{"IBMCLOUD_CS_API_ENDPOINT=not-a-url"}
	inputs.Zone = ""
	if err := runner.Plan(context.Background(), inputs); err == nil || !strings.Contains(err.Error(), "invalid container_service endpoint") {
		t.Fatalf("invalid override error = %v", err)
	}
	if len(discovery.environs) != 1 {
		t.Fatalf("discovery ran with invalid override: %d calls", len(discovery.environs))
	}
}

func TestMissingFzfUsesTheSameMissingInputError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	runner := newRunner(t.TempDir(), &fakeTerraform{})
	runner.Terminal = func() bool { return true }
	inputs := configuredInputs(t)
	inputs.Flavor = ""
	err := runner.Plan(context.Background(), inputs)
	var missing *prompt.MissingInputError
	if err == nil || !errors.As(err, &missing) || !strings.Contains(err.Error(), "missing required input(s): flavor") {
		t.Fatalf("missing fzf error = %v", err)
	}
}

func TestNormalizationAndGeneratedNames(t *testing.T) {
	if got, err := normalizeVersion("openshift", "1.31.4"); err != nil || got != "1.31_openshift" {
		t.Fatalf("openshift = %q, %v", got, err)
	}
	owner, err := normalizeOwner("Example Owner!")
	if err != nil || owner != "example-owner" {
		t.Fatalf("owner = %q, %v", owner, err)
	}
	if got := generatedName(owner, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "deadbeef"); got != "example-ow-260102030405-deadbeef" {
		t.Fatalf("generated = %q", got)
	}
}
