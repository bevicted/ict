package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bevicted/ict/internal/workflow"
)

func TestSplitLifecycleGrammarRejectsCreate(t *testing.T) {
	backendPath := filepath.Join(t.TempDir(), "backend.json")
	contextPath := filepath.Join(t.TempDir(), "context.json")
	resultPath := filepath.Join(t.TempDir(), "result.json")
	parsed, command, err := Parse([]string{"plan", "fixture", "--config", "config.yaml", "--provider", "vpc-gen2", "--subnet-id", "subnet-existing", "--backend-config", backendPath, "--result-file", contextPath})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan <state-id>" || command.Plan.StateID != "fixture" || command.Plan.Provider != "vpc-gen2" || command.Plan.BackendConfig != backendPath || command.Plan.ResultFile != contextPath {
		t.Fatalf("plan = %#v", command.Plan)
	}
	parsed, command, err = Parse([]string{"apply", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath, "--auto-approve"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "apply <state-id>" || command.Apply.StateID != "fixture" || !command.Apply.AutoApprove {
		t.Fatalf("apply = %#v", command.Apply)
	}
	parsed, command, err = Parse([]string{"destroy", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "destroy <state-id>" || command.Destroy.StateID != "fixture" {
		t.Fatalf("destroy = %#v", command.Destroy)
	}
	for _, args := range [][]string{
		{"create", "fixture"},
		{"plan"},
		{"plan", "fixture", "--backend-config", backendPath},
		{"apply", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath, "--name", "replacement"},
		{"destroy", "fixture", "--context-file", contextPath, "--backend-config", backendPath},
	} {
		if _, _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) accepted invalid lifecycle syntax", args)
		}
	}
}

func TestApplyRequiresAutoApproveBeforeWorkflow(t *testing.T) {
	backendPath := filepath.Join(t.TempDir(), "backend.json")
	contextPath := filepath.Join(t.TempDir(), "context.json")
	resultPath := filepath.Join(t.TempDir(), "result.json")
	parsed, command, err := Parse([]string{"apply", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := (Runner{Workflow: workflow.Runner{}}).Run(context.Background(), parsed, command); err == nil || !strings.Contains(err.Error(), "--auto-approve") {
		t.Fatalf("apply error = %v", err)
	}
}

func TestLifecycleRejectsInvalidStateIDBeforeWorkflow(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	backendPath := filepath.Join(t.TempDir(), "backend.json")
	contextPath := filepath.Join(t.TempDir(), "context.json")
	resultPath := filepath.Join(t.TempDir(), "result.json")
	for _, args := range [][]string{
		{"plan", "../outside", "--backend-config", backendPath, "--result-file", contextPath},
		{"apply", "../outside", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath, "--auto-approve"},
		{"destroy", "../outside", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath},
	} {
		parsed, command, err := Parse(args)
		if err != nil {
			t.Fatal(err)
		}
		if err := Run(context.Background(), parsed, command); err == nil || !strings.Contains(err.Error(), "invalid state ID") {
			t.Fatalf("Run error = %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
		t.Fatalf("invalid state ID created state root: %v", err)
	}
}

func TestConfigCommandsParseAndDispatchWithoutLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ntargets:\n  example:\n    providers: [classic]\n    default_region: us-south\n    endpoints:\n      iam: https://iam.example.invalid\n      container_service: https://containers.example.invalid\n      global_tagging: https://tagging.example.invalid\n      resource_management: https://management.example.invalid\n      resource_controller: https://controller.example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, command, err := Parse([]string{"config", "get", "targets.example.endpoints.iam", "--config", path})
	if err != nil {
		t.Fatal(err)
	}
	if err := (Runner{}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
}
