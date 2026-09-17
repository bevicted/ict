package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	parsed, command, err = Parse([]string{"review", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "review <state-id>" || command.Review.StateID != "fixture" || command.Review.ContextFile != contextPath || command.Review.BackendConfig != backendPath || command.Review.ResultFile != resultPath {
		t.Fatalf("review = %#v", command.Review)
	}
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	parsed, command, err = Parse([]string{"apply", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath, "--auth-manifest-file", manifestPath, "--auth-output-dir", outputDir, "--auto-approve"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "apply <state-id>" || command.Apply.StateID != "fixture" || !command.Apply.AutoApprove || command.Apply.AuthManifestFile != manifestPath || command.Apply.AuthOutputDir != outputDir {
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
		{"review", "fixture", "--context-file", contextPath, "--backend-config", backendPath},
		{"apply", "fixture", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath, "--name", "replacement"},
		{"destroy", "fixture", "--context-file", contextPath, "--backend-config", backendPath},
	} {
		if _, _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) accepted invalid lifecycle syntax", args)
		}
	}
}

type cleanupTerraform struct {
	calls   [][]string
	tfvars  [][]byte
	cleanup error
}

func (f *cleanupTerraform) Run(_ context.Context, _ []string, _ io.Writer, _ io.Writer, _ string, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	for _, arg := range args {
		if path, ok := strings.CutPrefix(arg, "-var-file="); ok {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			f.tfvars = append(f.tfvars, contents)
		}
	}
	if len(args) > 1 && args[1] == "plan" {
		return os.WriteFile(filepath.Join(strings.TrimPrefix(args[0], "-chdir="), ".cluster", "create.tfplan"), []byte("fixture plan"), 0o600)
	}
	if len(args) > 1 && args[1] == "destroy" && strings.Contains(args[0], "ict-auth-cleanup-") {
		return f.cleanup
	}
	return nil
}

func (f *cleanupTerraform) Output(context.Context, []string, string, ...string) ([]byte, error) {
	return nil, errors.New("unexpected auth acquisition")
}

func TestCLIDestroyReportsSanitizedCompanionCleanupFailure(t *testing.T) {
	backendPath := filepath.Join(t.TempDir(), "backend.json")
	if err := os.WriteFile(backendPath, []byte(`{"version":1,"bucket":"ict-state-bucket","key":"allocations/cluster-123.tfstate","region":"us-south","endpoint":"https://s3.us-south.cloud-object-storage.appdomain.cloud","skip_credentials_validation":true,"skip_metadata_api_check":true,"skip_region_validation":true,"skip_requesting_account_id":true,"force_path_style":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := "version: 1\ntargets:\n  example:\n    providers: [vpc-gen2]\n    default_region: us-south\n    endpoints:\n      iam: https://iam.example.invalid\n      container_service: https://containers.example.invalid\n      global_tagging: https://tagging.example.invalid\n      resource_management: https://management.example.invalid\n      resource_controller: https://controller.example.invalid\n      vpc: https://vpc.{region}.example.invalid\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	contextPath, resultPath := filepath.Join(t.TempDir(), "context.json"), filepath.Join(t.TempDir(), "destroy.json")
	fixture := &cleanupTerraform{cleanup: errors.New("provider stale secret 404 synthetic detail")}
	planArgs := []string{"plan", "allocation-123", "--config", configPath, "--target", "example", "--provider", "vpc-gen2", "--platform", "kubernetes", "--version", "1.31.9", "--resource-group", "fixture-group", "--zone", "us-south-1", "--flavor", "bx2.2x8", "--name", "fixture-cluster", "--backend-config", backendPath, "--result-file", contextPath, "--auth-allocation-uid", "allocation-123", "--auth-vpn-server-id", "vpn-1", "--auth-secrets-manager-id", "sm-1", "--auth-secrets-manager-region", "eu-gb", "--auth-secret-group-id", "group-1", "--auth-certificate-template", "client-template", "--auth-issuer", "issuer-1", "--auth-ttl", "168h"}
	parsed, command, err := Parse(planArgs)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Runner{Workflow: workflow.Runner{Workspace: filepath.Join(t.TempDir(), "plan"), Terraform: fixture, Terminal: func() bool { return false }}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("changed defaults are not destroy inputs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, command, err = Parse([]string{"destroy", "allocation-123", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath})
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	if err := (Runner{Workflow: workflow.Runner{Workspace: filepath.Join(t.TempDir(), "destroy"), Terraform: fixture, Terminal: func() bool { return false }, Stderr: &stderr}}).Run(context.Background(), parsed, command); err != nil {
		t.Fatal(err)
	}
	var result workflow.OperationResult
	if err := json.Unmarshal(mustReadCLI(t, resultPath), &result); err != nil || result.Operation != "destroy" || result.AuthCleanup != "failed" {
		t.Fatalf("destroy result = %#v, %v", result, err)
	}
	if stderr.String() != "ict: auth cleanup unavailable\n" || strings.Contains(stderr.String(), "404") || len(fixture.calls) != 6 || len(fixture.tfvars) != 3 || strings.Contains(string(fixture.tfvars[2]), "cluster_name") || !strings.Contains(string(fixture.tfvars[2]), `"auth_secrets_manager_id":"sm-1"`) {
		t.Fatalf("CLI destroy did not use bounded frozen cleanup: stderr=%q calls=%#v tfvars=%q", stderr.String(), fixture.calls, fixture.tfvars)
	}
}

func mustReadCLI(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
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
		{"review", "../outside", "--context-file", contextPath, "--backend-config", backendPath, "--result-file", resultPath},
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
