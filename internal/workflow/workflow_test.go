package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		return os.WriteFile(filepath.Join(f.workspace, ictterraform.PlanName), []byte("saved plan"), 0o644)
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

func newRunner(workspace string, fake *fakeTerraform) Runner {
	fake.workspace = workspace
	return Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }}
}

func actionNames(calls [][]string) []string {
	result := make([]string, 0, len(calls))
	for _, call := range calls {
		result = append(result, call[1])
	}
	return result
}

func TestCreateSavesReviewsAndAppliesExactPlan(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ict", "new")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredInputs(t)
	inputs.AutoApprove = true
	if err := runner.Create(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(actionNames(fake.calls), ","), "init,plan,apply"; got != want {
		t.Fatalf("actions = %q, want %q", got, want)
	}
	planCall, applyCall := strings.Join(fake.calls[1], " "), strings.Join(fake.calls[2], " ")
	if !strings.Contains(planCall, "-out=.cluster/create.tfplan") || !strings.Contains(planCall, "-var-file="+filepath.Join(workspace, ictterraform.TFVarsName)) {
		t.Fatalf("plan call = %q", planCall)
	}
	if got, want := applyCall, "-chdir="+workspace+" apply -input=false .cluster/create.tfplan"; got != want {
		t.Fatalf("apply call = %q, want %q", got, want)
	}
	info, err := os.Stat(filepath.Join(workspace, ictterraform.PlanName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved plan = %v, %v", info, err)
	}
	for _, name := range []string{ictterraform.TFVarsName, ictterraform.ContextName} {
		info, err := os.Stat(filepath.Join(workspace, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("runtime artifact %s = %v, %v", name, info, err)
		}
	}
}

func TestCreateApprovalPaths(t *testing.T) {
	for _, test := range []struct {
		name      string
		terminal  bool
		input     string
		auto      bool
		wantError string
		wantGone  bool
		wantApply bool
	}{
		{name: "literal yes", terminal: true, input: "yes\n", wantApply: true},
		{name: "decline", terminal: true, input: "Yes\n", wantGone: true},
		{name: "noninteractive", wantError: "auto-approve"},
		{name: "auto approve", auto: true, wantApply: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "workspace")
			fake := &fakeTerraform{}
			runner := newRunner(workspace, fake)
			runner.Terminal = func() bool { return test.terminal }
			runner.Stdin = strings.NewReader(test.input)
			var output strings.Builder
			runner.Stdout = &output
			inputs := configuredInputs(t)
			inputs.AutoApprove = test.auto
			err := runner.Create(context.Background(), inputs)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v", err)
				}
				if _, statErr := os.Stat(workspace); !os.IsNotExist(statErr) {
					t.Fatalf("preflight created workspace: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(workspace)
			if test.wantGone != os.IsNotExist(statErr) {
				t.Fatalf("workspace stat = %v, wantGone=%t", statErr, test.wantGone)
			}
			gotApply := strings.Contains(strings.Join(actionNames(fake.calls), ","), "apply")
			if gotApply != test.wantApply {
				t.Fatalf("actions = %#v", fake.calls)
			}
			if !test.auto && !test.wantGone && !strings.Contains(output.String(), "Enter a value") {
				t.Fatalf("confirmation was not displayed: %q", output.String())
			}
		})
	}
}

func TestCreatePreflightFailureDoesNotReserveWorkspace(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredInputs(t)
	inputs.AutoApprove = true
	inputs.Zone = "not-a-zone"
	if err := runner.Create(context.Background(), inputs); err == nil {
		t.Fatal("invalid input was accepted")
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("preflight created workspace: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("preflight called Terraform: %#v", fake.calls)
	}
}

func TestCreateReservesWorkspaceAndPreservesFailures(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredInputs(t)
	inputs.AutoApprove = true
	if err := runner.Create(context.Background(), inputs); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing workspace error = %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("existing workspace called Terraform: %#v", fake.calls)
	}

	for _, test := range []struct {
		name     string
		set      func(*fakeTerraform)
		wantPlan bool
	}{
		{name: "init", set: func(f *fakeTerraform) { f.initErr = errors.New("init failed") }},
		{name: "plan", set: func(f *fakeTerraform) { f.planErr = errors.New("plan failed") }},
		{name: "apply", set: func(f *fakeTerraform) { f.applyErr = errors.New("apply failed") }, wantPlan: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "workspace")
			fake := &fakeTerraform{}
			test.set(fake)
			runner := newRunner(workspace, fake)
			inputs := configuredInputs(t)
			inputs.AutoApprove = true
			if err := runner.Create(context.Background(), inputs); err == nil {
				t.Fatal("create succeeded")
			}
			if _, err := os.Stat(workspace); err != nil {
				t.Fatalf("failed create removed workspace: %v", err)
			}
			if test.wantPlan {
				if _, err := os.Stat(filepath.Join(workspace, ictterraform.PlanName)); err != nil {
					t.Fatalf("failed apply removed saved plan: %v", err)
				}
			}
		})
	}
}

func TestCreatePreservesWorkspaceOnPostReservationFilesystemFailure(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	runner.Materialize = func(string) error { return errors.New("materialization failed") }
	inputs := configuredInputs(t)
	inputs.AutoApprove = true
	if err := runner.Create(context.Background(), inputs); err == nil || !strings.Contains(err.Error(), "materialization failed") {
		t.Fatalf("create error = %v", err)
	}
	if _, err := os.Stat(workspace); err != nil {
		t.Fatalf("filesystem failure removed workspace: %v", err)
	}
}

func TestDestroyUsesStateAsAuthority(t *testing.T) {
	t.Run("no state removes directly", func(t *testing.T) {
		workspace := t.TempDir()
		fake := &fakeTerraform{}
		runner := newRunner(workspace, fake)
		if err := runner.Destroy(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("no-state destroy called Terraform: %#v", fake.calls)
		}
		if _, err := os.Stat(workspace); !os.IsNotExist(err) {
			t.Fatalf("workspace remains: %v", err)
		}
	})

	t.Run("state destroys without state list", func(t *testing.T) {
		workspace := filepath.Join(t.TempDir(), "workspace")
		fake := &fakeTerraform{}
		runner := newRunner(workspace, fake)
		inputs := configuredInputs(t)
		inputs.AutoApprove = true
		if err := runner.Create(context.Background(), inputs); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, "terraform.tfstate"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		fake.calls = nil
		if err := runner.Destroy(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got, want := strings.Join(actionNames(fake.calls), ","), "init,destroy"; got != want {
			t.Fatalf("destroy actions = %q, want %q", got, want)
		}
		if _, err := os.Stat(workspace); !os.IsNotExist(err) {
			t.Fatalf("workspace remains: %v", err)
		}
	})
}

func TestRecoveryDataBindsSavedValues(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	inputs := configuredInputs(t)
	inputs.AutoApprove = true
	if err := runner.Create(context.Background(), inputs); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(workspace, ictterraform.ContextName))
	if err != nil {
		t.Fatal(err)
	}
	var recovery RecoveryContext
	if err := json.Unmarshal(data, &recovery); err != nil || recovery.TFVarsSHA256 == "" {
		t.Fatalf("recovery = %#v, %v", recovery, err)
	}
}
