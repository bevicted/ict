package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bevicted/ict/internal/config"
)

func TestKongParsesICTEnvironment(t *testing.T) {
	t.Setenv("ICT_TARGET", "example")
	t.Setenv("ICT_PROVIDER", "vpc-gen2")
	t.Setenv("ICT_PLATFORM", "kubernetes")
	t.Setenv("ICT_VERSION", "1.31.4")
	t.Setenv("ICT_RESOURCE_GROUP", "fixture-group")
	t.Setenv("ICT_ZONE", "us-south-1")
	t.Setenv("ICT_FLAVOR", "bx2.2x8")
	t.Setenv("ICT_VPC_ID", "vpc-existing")
	t.Setenv("ICT_SUBNET_IDS", "subnet-existing")
	t.Setenv("ICT_PUBLIC_GATEWAY_IDS", "gateway-existing")
	t.Setenv("ICT_CONFIG", "environment-config.yaml")
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--name", "fixture-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Config != "config.yaml" || command.Plan.Target != "example" || command.Plan.Provider != "vpc-gen2" || command.Plan.Zone != "us-south-1" || command.Plan.VPCID != "vpc-existing" || strings.Join(command.Plan.SubnetIDs, ",") != "subnet-existing" || strings.Join(command.Plan.PublicGatewayIDs, ",") != "gateway-existing" {
		t.Fatalf("parsed command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestKongUsesXDGConfigWhenConfigValueIsEmpty(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("ICT_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", configHome)

	for _, provider := range []string{"vpc-gen2", "classic", "satellite"} {
		t.Run(provider, func(t *testing.T) {
			_, command, err := Parse([]string{"plan", "--config=", "--provider", provider})
			if err != nil {
				t.Fatal(err)
			}
			path, err := config.DiscoverPath(command.Plan.Config)
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(configHome, "ict", "config.yaml")
			if path != want {
				t.Fatalf("config path = %q, want %q", path, want)
			}
		})
	}
}

func TestKongParsesVPCReuseInputs(t *testing.T) {
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--target", "example", "--provider", "vpc-gen2", "--platform", "kubernetes", "--version", "1.31.4", "--resource-group", "fixture-group", "--zone", "us-south-1", "--flavor", "bx2.2x8", "--vpc-id", "vpc-existing", "--subnet-id", "subnet-existing", "--public-gateway-id", "gateway-existing"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.VPCID != "vpc-existing" || strings.Join(command.Plan.SubnetIDs, ",") != "subnet-existing" || strings.Join(command.Plan.PublicGatewayIDs, ",") != "gateway-existing" {
		t.Fatalf("parsed VPC reuse command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestKongParsesClassicInputs(t *testing.T) {
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--target", "example", "--provider", "classic", "--platform", "openshift", "--version", "1.31.4", "--resource-group", "fixture-group", "--datacenter", "dal10", "--machine-type", "bx2.2x8", "--public-vlan-id", "12345", "--private-vlan-id", "67890"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Provider != "classic" || command.Plan.Datacenter != "dal10" || command.Plan.PrivateVLANID != "67890" {
		t.Fatalf("parsed classic command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestKongParsesSatelliteInputs(t *testing.T) {
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--target", "example", "--provider", "satellite", "--platform", "openshift", "--version", "4.17.3", "--resource-group", "fixture-group", "--satellite-zone", "us-south-1", "--satellite-zone", "us-south-2", "--satellite-zone", "us-south-3", "--satellite-managed-from", "us-south", "--satellite-host-image", "rhel-8-synthetic", "--satellite-ssh-public-key", "key.pub"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Provider != "satellite" || len(command.Plan.SatelliteZones) != 3 || !strings.HasSuffix(command.Plan.SatelliteSSHPublicKeyPath, "key.pub") {
		t.Fatalf("parsed Satellite command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestDestroyRejectsReplacementInputs(t *testing.T) {
	_, _, err := Parse([]string{"destroy", "--name", "replacement"})
	if err == nil {
		t.Fatal("destroy accepted replacement input")
	}
}

func TestConfigCommandsParseAndDispatchWithoutWorkflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
targets:
  example:
    providers: [classic]
    default_region: us-south
    endpoints:
      iam: https://iam.example.invalid
      container_service: https://containers.example.invalid
      global_tagging: https://global-tagging.example.invalid
      resource_management: https://resource-management.example.invalid
      resource_controller: https://resource-controller.example.invalid
`), 0o600); err != nil {
		t.Fatal(err)
	}

	parsed, command, err := Parse([]string{"config", "get", "targets.example.endpoints.iam", "--config", path})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Command(); got != "config get <path>" {
		t.Fatalf("parsed command = %q", got)
	}
	if command.Config.Get.Config != path || command.Config.Get.Path != "targets.example.endpoints.iam" {
		t.Fatalf("config get = %#v", command.Config.Get)
	}
	var output bytes.Buffer
	if err := (Runner{Config: config.Runner{Stdout: &output}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "https://iam.example.invalid\n" {
		t.Fatalf("config get output = %q", got)
	}

	parsed, command, err = Parse([]string{"config", "set", "targets.example.default_region", "eu-gb", "--config", path})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Command(); got != "config set <path> <yaml-value>" {
		t.Fatalf("parsed command = %q", got)
	}
	if command.Config.Set.Config != path || command.Config.Set.Path != "targets.example.default_region" || command.Config.Set.Value != "eu-gb" {
		t.Fatalf("config set = %#v", command.Config.Set)
	}
	if err := (Runner{Config: config.Runner{}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	updated, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Targets["example"].DefaultRegion != "eu-gb" {
		t.Fatalf("set default region = %q", updated.Targets["example"].DefaultRegion)
	}

	t.Setenv("ICT_CONFIG", path)
	parsed, command, err = Parse([]string{"config", "show"})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Command(); got != "config show" {
		t.Fatalf("parsed command = %q", got)
	}
	if command.Config.Show.Config != path {
		t.Fatalf("config show path = %q, want %q", command.Config.Show.Config, path)
	}
	output.Reset()
	if err := (Runner{Config: config.Runner{Stdout: &output}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "version: 1\n") {
		t.Fatalf("config show output = %q", output.String())
	}

	editPath := filepath.Join(t.TempDir(), "config with spaces.yaml")
	parsed, command, err = Parse([]string{"config", "edit", "--config", editPath})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Command(); got != "config edit" {
		t.Fatalf("parsed command = %q", got)
	}
	if command.Config.Edit.Config != editPath {
		t.Fatalf("config edit path = %q, want %q", command.Config.Edit.Config, editPath)
	}
	contents := "malformed: [\n"
	if err := (Runner{Config: config.Runner{Stdin: strings.NewReader(contents), Terminal: func() bool { return false }}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(editPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(stored); got != contents {
		t.Fatalf("config edit contents = %q, want %q", got, contents)
	}
}
