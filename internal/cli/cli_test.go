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

func TestCreateGrammarParsesApprovalAndRejectsPlan(t *testing.T) {
	t.Setenv("ICT_AUTO_APPROVE", "true")
	parsed, command, err := Parse([]string{"create", "--config", "config.yaml", "--name", "fixture-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "create" || command.Create.Config != "config.yaml" || command.Create.Name != "fixture-cluster" || !command.Create.AutoApprove {
		t.Fatalf("create = %#v", command.Create)
	}
	if _, _, err := Parse([]string{"plan"}); err == nil {
		t.Fatal("plan command was accepted")
	}
}

func TestCreateStateIDAndInputs(t *testing.T) {
	t.Setenv("ICT_STATE_ID", "from-environment")
	_, command, err := Parse([]string{"create", "--state-id", "from-flag", "--provider", "vpc-gen2", "--subnet-id", "subnet-existing", "--auto-approve"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Create.StateID != "from-flag" || command.Create.Provider != "vpc-gen2" || strings.Join(command.Create.SubnetIDs, ",") != "subnet-existing" || !command.Create.AutoApprove {
		t.Fatalf("create = %#v", command.Create)
	}
	_, command, err = Parse([]string{"create"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Create.StateID != "from-environment" {
		t.Fatalf("state ID = %q", command.Create.StateID)
	}
}

func TestLifecycleRejectsInvalidStateIDBeforeWorkflow(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	parsed, command, err := Parse([]string{"create", "--state-id", "../outside", "--auto-approve"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), parsed, command); err == nil || !strings.Contains(err.Error(), "invalid state ID") {
		t.Fatalf("Run error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
		t.Fatalf("invalid state ID created state root: %v", err)
	}
}

func TestListAliasesProduceIdenticalOutput(t *testing.T) {
	stateHome := t.TempDir()
	root := filepath.Join(stateHome, "ict")
	t.Setenv("XDG_STATE_HOME", stateHome)
	for _, name := range []string{"zeta", "alpha", "failed"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"list", "ls"} {
		parsed, command, err := Parse([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := (Runner{Stdout: &output}).Run(context.Background(), parsed, command); err != nil {
			t.Fatal(err)
		}
		if got, want := output.String(), "alpha\nfailed\nzeta\n"; got != want {
			t.Fatalf("output = %q, want %q", got, want)
		}
	}
}

func TestConfigCommandsParseAndDispatchWithoutWorkflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ntargets:\n  example:\n    providers: [classic]\n    default_region: us-south\n    endpoints:\n      iam: https://iam.example.invalid\n      container_service: https://containers.example.invalid\n      global_tagging: https://tagging.example.invalid\n      resource_management: https://management.example.invalid\n      resource_controller: https://controller.example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, command, err := Parse([]string{"config", "get", "targets.example.endpoints.iam", "--config", path})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := (Runner{Config: config.Runner{Stdout: &output}, Workflow: workflow.Runner{}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "https://iam.example.invalid\n" {
		t.Fatalf("config output = %q", got)
	}
}
