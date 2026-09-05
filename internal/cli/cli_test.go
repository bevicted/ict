package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bevicted/ict/internal/config"
	"github.com/bevicted/ict/internal/workflow"
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
	t.Setenv("ICT_SATELLITE_LOCATION_ID", "location-existing")
	t.Setenv("ICT_SATELLITE_SSH_KEY_ID", "key-existing")
	t.Setenv("ICT_SATELLITE_WORKER_INSTANCE_IDS", "worker-2,worker-1")
	t.Setenv("ICT_CONFIG", "environment-config.yaml")
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--name", "fixture-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Config != "config.yaml" || command.Plan.Target != "example" || command.Plan.Provider != "vpc-gen2" || command.Plan.Zone != "us-south-1" || command.Plan.VPCID != "vpc-existing" || strings.Join(command.Plan.SubnetIDs, ",") != "subnet-existing" || strings.Join(command.Plan.PublicGatewayIDs, ",") != "gateway-existing" || command.Plan.SatelliteLocationID != "location-existing" || command.Plan.SatelliteSSHKeyID != "key-existing" || strings.Join(command.Plan.SatelliteWorkerInstanceIDs, ",") != "worker-2,worker-1" {
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
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--target", "example", "--provider", "satellite", "--platform", "openshift", "--version", "4.17.3", "--resource-group", "fixture-group", "--satellite-zone", "us-south-1", "--satellite-zone", "us-south-2", "--satellite-zone", "us-south-3", "--satellite-location-id", "location-existing", "--satellite-host-image", "rhel-8-synthetic", "--satellite-ssh-key-id", "key-existing", "--satellite-worker-instance-id", "worker-1", "--subnet-id", "subnet-3", "--subnet-id", "subnet-1", "--subnet-id", "subnet-2", "--public-gateway-id", "gateway-2", "--public-gateway-id", "gateway-3", "--public-gateway-id", "gateway-1"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Provider != "satellite" || len(command.Plan.SatelliteZones) != 3 || command.Plan.SatelliteLocationID != "location-existing" || command.Plan.SatelliteSSHKeyID != "key-existing" || strings.Join(command.Plan.SatelliteWorkerInstanceIDs, ",") != "worker-1" || strings.Join(command.Plan.SubnetIDs, ",") != "subnet-3,subnet-1,subnet-2" || strings.Join(command.Plan.PublicGatewayIDs, ",") != "gateway-2,gateway-3,gateway-1" {
		t.Fatalf("parsed Satellite command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestKongParsesLifecycleStateID(t *testing.T) {
	for _, commandName := range []string{"plan", "create", "destroy"} {
		t.Run(commandName, func(t *testing.T) {
			t.Setenv("ICT_STATE_ID", "from-environment")
			_, command, err := Parse([]string{commandName, "--state-id", "from-flag"})
			if err != nil {
				t.Fatal(err)
			}
			var stateID string
			switch commandName {
			case "plan":
				stateID = command.Plan.StateID
			case "create":
				stateID = command.Create.StateID
			case "destroy":
				stateID = command.Destroy.StateID
			}
			if stateID != "from-flag" {
				t.Fatalf("state ID = %q, want flag value", stateID)
			}
			_, command, err = Parse([]string{commandName})
			if err != nil {
				t.Fatal(err)
			}
			switch commandName {
			case "plan":
				stateID = command.Plan.StateID
			case "create":
				stateID = command.Create.StateID
			case "destroy":
				stateID = command.Destroy.StateID
			}
			if stateID != "from-environment" {
				t.Fatalf("state ID = %q, want environment value", stateID)
			}
		})
	}
}

func TestKongDefaultsLifecycleStateID(t *testing.T) {
	previous, set := os.LookupEnv("ICT_STATE_ID")
	if err := os.Unsetenv("ICT_STATE_ID"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if set {
			_ = os.Setenv("ICT_STATE_ID", previous)
		}
	})
	for _, commandName := range []string{"plan", "create", "destroy"} {
		t.Run(commandName, func(t *testing.T) {
			_, command, err := Parse([]string{commandName})
			if err != nil {
				t.Fatal(err)
			}
			var stateID string
			switch commandName {
			case "plan":
				stateID = command.Plan.StateID
			case "create":
				stateID = command.Create.StateID
			case "destroy":
				stateID = command.Destroy.StateID
			}
			if stateID != "default" {
				t.Fatalf("state ID = %q, want default", stateID)
			}
		})
	}
}

func TestLifecycleRejectsEmptyStateID(t *testing.T) {
	for _, args := range [][]string{
		{"plan", "--state-id="},
		{"plan"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if len(args) == 1 {
				t.Setenv("ICT_STATE_ID", "")
			}
			parsed, command, err := Parse(args)
			if err != nil {
				t.Fatal(err)
			}
			if err := Run(context.Background(), parsed, command); err == nil || !strings.Contains(err.Error(), "invalid state ID") {
				t.Fatalf("Run error = %v, want invalid state ID", err)
			}
		})
	}
}

func TestStateIDIsLifecycleScoped(t *testing.T) {
	for _, args := range [][]string{
		{"--state-id", "one", "plan"},
		{"config", "show", "--state-id", "one"},
	} {
		if _, _, err := Parse(args); err == nil {
			t.Fatalf("Parse(%q) accepted a non-lifecycle state ID", args)
		}
	}
}

func TestListAliasesProduceIdenticalOutput(t *testing.T) {
	stateHome := t.TempDir()
	root := filepath.Join(stateHome, "ict")
	t.Setenv("XDG_STATE_HOME", stateHome)
	for _, name := range []string{"zeta", "alpha", "plan-only"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{"list", "ls"} {
		t.Run(name, func(t *testing.T) {
			parsed, command, err := Parse([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			if got := parsed.Command(); got != "list" {
				t.Fatalf("parsed command = %q, want list", got)
			}
			var output bytes.Buffer
			if err := (Runner{Stdout: &output}).Run(context.Background(), parsed, command); err != nil {
				t.Fatal(err)
			}
			if got, want := output.String(), "alpha\nplan-only\nzeta\n"; got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestListRejectsStateID(t *testing.T) {
	for _, args := range [][]string{{"list", "--state-id", "one"}, {"ls", "--state-id", "one"}} {
		if _, _, err := Parse(args); err == nil {
			t.Fatalf("Parse(%q) accepted a state ID", args)
		}
	}
}

func TestLifecycleWorkspaceSelection(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	original := workflow.Runner{Workspace: "injected-workspace"}
	runner, err := (Runner{Workflow: original}).lifecycle("selected-state")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(stateHome, "ict", "selected-state")
	if runner.Workspace != want {
		t.Fatalf("workspace = %q, want %q", runner.Workspace, want)
	}
	if original.Workspace != "injected-workspace" {
		t.Fatalf("original runner workspace = %q", original.Workspace)
	}
	if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
		t.Fatalf("workspace selection created the state root: %v", err)
	}
}

func TestLifecycleRejectsInvalidStateIDBeforeWorkflow(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	parsed, command, err := Parse([]string{"plan", "--state-id", "../outside"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), parsed, command); err == nil || !strings.Contains(err.Error(), "invalid state ID") {
		t.Fatalf("Run error = %v, want invalid state ID", err)
	}
	if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
		t.Fatalf("invalid state ID created the state root: %v", err)
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
