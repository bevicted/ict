package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	ictterraform "github.com/bevicted/ict/internal/terraform"
)

type fakeTerraform struct {
	workspace  string
	initErr    error
	planErr    error
	applyErr   error
	destroyErr error
	calls      [][]string
}

func (f *fakeTerraform) Run(_ context.Context, _ []string, _ io.Writer, _ io.Writer, _ string, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	switch args[1] {
	case "init":
		return f.initErr
	case "plan":
		if f.planErr != nil {
			return f.planErr
		}
		return os.WriteFile(filepath.Join(f.workspace, ictterraform.PlanName), []byte("saved plan"), 0o600)
	case "apply":
		return f.applyErr
	case "destroy":
		return f.destroyErr
	}
	return nil
}

func (f *fakeTerraform) Output(context.Context, []string, string, ...string) ([]byte, error) {
	return nil, errors.New("unexpected Terraform output call")
}

const testConfig = `version: 1
targets:
  example:
    providers: [vpc-gen2]
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

func backendConfig() ictterraform.BackendConfig {
	return ictterraform.BackendConfig{Version: 1, Bucket: "ict-state-bucket", Key: "allocations/cluster-123.tfstate", Region: "us-south", Endpoint: "https://s3.us-south.cloud-object-storage.appdomain.cloud", SkipCredentialsValidation: true, SkipMetadataAPICheck: true, SkipRegionValidation: true, SkipRequestingAccountID: true, ForcePathStyle: true}
}

func newRunner(workspace string, fake *fakeTerraform) Runner {
	fake.workspace = workspace
	return Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }}
}

func TestResolveNamePrefixingAndLimits(t *testing.T) {
	now := time.Date(2026, 9, 7, 11, 29, 13, 0, time.UTC)
	runner := Runner{Environ: []string{"USER=Fallback Owner"}, Now: func() time.Time { return now }, Suffix: func() string { return "ab12cd34" }}

	name, err := runner.resolveName(Inputs{Name: "unchanged-name"}, 32)
	if err != nil || name != "unchanged-name" {
		t.Fatalf("explicit no-prefix name = %q, %v", name, err)
	}
	name, err = runner.resolveName(Inputs{Owner: "Explicit Owner"}, 32)
	if err != nil || name != "explicit-o-260907112913-ab12cd34" {
		t.Fatalf("owner generated name = %q, %v", name, err)
	}
	for _, test := range []struct {
		provider string
		limit    int
		pattern  *regexp.Regexp
	}{{"VPC", 32, vpcClusterPattern}, {"Classic", 35, classicClusterPattern}, {"Satellite", 44, satelliteClusterPattern}} {
		t.Run(test.provider, func(t *testing.T) {
			name, err := runner.resolveName(Inputs{Prefix: "SERVITOR"}, test.limit)
			if err != nil || len(name) > test.limit || !test.pattern.MatchString(name) {
				t.Fatalf("generated prefixed name = %q, %v", name, err)
			}
		})
	}
}

func TestPlanApplyDestroyUseFrozenMetadataAndFreshWorkspaces(t *testing.T) {
	backend := backendConfig()
	planWorkspace := filepath.Join(t.TempDir(), "plan")
	contextPath := filepath.Join(t.TempDir(), "context.json")
	planFake := &fakeTerraform{}
	planRunner := newRunner(planWorkspace, planFake)
	if err := planRunner.Plan(context.Background(), "allocation-123", configuredInputs(t), backend, contextPath); err != nil {
		t.Fatal(err)
	}
	if got, want := actionNames(planFake.calls), []string{"init", "plan"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plan actions = %#v, want %#v", got, want)
	}
	handoff, err := ReadPlanResult(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	if handoff.StateID != "allocation-123" || handoff.Values.ClusterName != "fixture-cluster" || !reflect.DeepEqual(handoff.Backend, backend) {
		t.Fatalf("context = %#v", handoff)
	}
	if strings.Contains(string(mustRead(t, contextPath)), "AWS_SECRET_ACCESS_KEY") {
		t.Fatal("context contains credentials")
	}

	applyWorkspace := filepath.Join(t.TempDir(), "apply")
	applyResult := filepath.Join(t.TempDir(), "apply-result.json")
	applyFake := &fakeTerraform{}
	applyRunner := newRunner(applyWorkspace, applyFake)
	if err := applyRunner.Apply(context.Background(), "allocation-123", contextPath, backend, applyResult); err != nil {
		t.Fatal(err)
	}
	assertOperationCalls(t, applyFake.calls, applyWorkspace, "apply", backend)
	assertOperationResult(t, applyResult, "apply", applyWorkspace)
	if _, err := os.Stat(filepath.Join(applyWorkspace, "terraform.tfstate")); !os.IsNotExist(err) {
		t.Fatalf("apply depended on local state: %v", err)
	}

	destroyWorkspace := filepath.Join(t.TempDir(), "destroy")
	destroyResult := filepath.Join(t.TempDir(), "destroy-result.json")
	destroyFake := &fakeTerraform{}
	destroyRunner := newRunner(destroyWorkspace, destroyFake)
	if err := destroyRunner.Destroy(context.Background(), "allocation-123", contextPath, backend, destroyResult); err != nil {
		t.Fatal(err)
	}
	assertOperationCalls(t, destroyFake.calls, destroyWorkspace, "destroy", backend)
	assertOperationResult(t, destroyResult, "destroy", destroyWorkspace)
}

func TestApplyDestroyRejectTamperingBeforeTerraform(t *testing.T) {
	backend := backendConfig()
	contextPath := writePlanContext(t, backend)
	for _, test := range []struct {
		name    string
		stateID string
		backend ictterraform.BackendConfig
		mutate  func([]byte) []byte
	}{
		{name: "mismatched identifier", stateID: "other", backend: backend},
		{name: "mismatched backend", stateID: "allocation-123", backend: func() ictterraform.BackendConfig { b := backend; b.Key = "allocations/other.tfstate"; return b }()},
		{name: "changed frozen values", stateID: "allocation-123", backend: backend, mutate: func(data []byte) []byte {
			return []byte(strings.Replace(string(data), "fixture-cluster", "replacement-cluster", 1))
		}},
		{name: "unknown field", stateID: "allocation-123", backend: backend, mutate: func(data []byte) []byte { return append(data[:len(data)-1], []byte(`,"credential":"secret"}`)...) }},
		{name: "trailing JSON", stateID: "allocation-123", backend: backend, mutate: func(data []byte) []byte { return append(data, []byte(`{}`)...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := contextPath
			if test.mutate != nil {
				path = filepath.Join(t.TempDir(), "tampered.json")
				if err := os.WriteFile(path, test.mutate(mustRead(t, contextPath)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fake := &fakeTerraform{}
			runner := newRunner(filepath.Join(t.TempDir(), "operation"), fake)
			err := runner.Apply(context.Background(), test.stateID, path, test.backend, filepath.Join(t.TempDir(), "result.json"))
			if err == nil {
				t.Fatal("tampered input was accepted")
			}
			if len(fake.calls) != 0 {
				t.Fatalf("tampered input called Terraform: %#v", fake.calls)
			}
		})
	}
}

func TestDestroyNeverTreatsMissingLocalStateOrBackendFailureAsSuccess(t *testing.T) {
	backend := backendConfig()
	contextPath := writePlanContext(t, backend)
	t.Run("empty remote state", func(t *testing.T) {
		workspace := filepath.Join(t.TempDir(), "fresh")
		resultPath := filepath.Join(t.TempDir(), "result.json")
		fake := &fakeTerraform{}
		if err := newRunner(workspace, fake).Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath); err != nil {
			t.Fatal(err)
		}
		assertOperationCalls(t, fake.calls, workspace, "destroy", backend)
	})
	t.Run("backend failure", func(t *testing.T) {
		fake := &fakeTerraform{initErr: errors.New("backend unavailable")}
		resultPath := filepath.Join(t.TempDir(), "result.json")
		err := newRunner(filepath.Join(t.TempDir(), "fresh"), fake).Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath)
		if err == nil || !strings.Contains(err.Error(), "backend unavailable") {
			t.Fatalf("destroy error = %v", err)
		}
		if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
			t.Fatalf("backend failure reported cleanup success: %v", err)
		}
	})
}

func TestFailedApplyCanBeFollowedByDestroy(t *testing.T) {
	backend := backendConfig()
	contextPath := writePlanContext(t, backend)
	applyFake := &fakeTerraform{applyErr: errors.New("apply failed")}
	if err := newRunner(filepath.Join(t.TempDir(), "apply"), applyFake).Apply(context.Background(), "allocation-123", contextPath, backend, filepath.Join(t.TempDir(), "apply-result.json")); err == nil {
		t.Fatal("apply unexpectedly succeeded")
	}
	destroyFake := &fakeTerraform{}
	if err := newRunner(filepath.Join(t.TempDir(), "destroy"), destroyFake).Destroy(context.Background(), "allocation-123", contextPath, backend, filepath.Join(t.TempDir(), "destroy-result.json")); err != nil {
		t.Fatal(err)
	}
	if got := actionNames(destroyFake.calls); !reflect.DeepEqual(got, []string{"init", "destroy"}) {
		t.Fatalf("destroy actions = %#v", got)
	}
}

func writePlanContext(t *testing.T, backend ictterraform.BackendConfig) string {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "plan")
	path := filepath.Join(t.TempDir(), "context.json")
	fake := &fakeTerraform{}
	if err := newRunner(workspace, fake).Plan(context.Background(), "allocation-123", configuredInputs(t), backend, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func actionNames(calls [][]string) []string {
	result := make([]string, 0, len(calls))
	for _, call := range calls {
		result = append(result, call[1])
	}
	return result
}

func assertOperationCalls(t *testing.T, calls [][]string, workspace, operation string, backend ictterraform.BackendConfig) {
	t.Helper()
	wantInit := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, backend.InitArgs()...)
	want := [][]string{wantInit, {"-chdir=" + workspace, operation, "-input=false", "-no-color", "-auto-approve", "-var-file=" + filepath.Join(workspace, ictterraform.TFVarsName)}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Terraform calls = %#v, want %#v", calls, want)
	}
}

func assertOperationResult(t *testing.T, path, operation, workspace string) {
	t.Helper()
	data := mustRead(t, path)
	var result OperationResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.Operation != operation || result.Workspace != workspace || len(data) > 4096 {
		t.Fatalf("operation result = %#v", result)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
