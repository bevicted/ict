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
	name, err = runner.resolveName(Inputs{}, 32)
	if err != nil || name != "fallback-o-260907112913-ab12cd34" {
		t.Fatalf("environment generated name = %q, %v", name, err)
	}
	name, err = (Runner{Environ: []string{}, Now: func() time.Time { return now }, Suffix: func() string { return "ab12cd34" }}).resolveName(Inputs{}, 32)
	if err != nil || name != "user-260907112913-ab12cd34" {
		t.Fatalf("default generated name = %q, %v", name, err)
	}

	for _, test := range []struct {
		provider string
		limit    int
		pattern  *regexp.Regexp
	}{
		{provider: "VPC", limit: 32, pattern: vpcClusterPattern},
		{provider: "Classic", limit: 35, pattern: classicClusterPattern},
		{provider: "Satellite", limit: 44, pattern: satelliteClusterPattern},
	} {
		t.Run(test.provider, func(t *testing.T) {
			name, err := runner.resolveName(Inputs{Owner: "ignored-owner", Prefix: "SERVITOR"}, test.limit)
			if err != nil || name != "servitor-260907112913-ab12cd34" || len(name) > test.limit || !test.pattern.MatchString(name) {
				t.Fatalf("generated prefixed name = %q, %v", name, err)
			}
			name, err = runner.resolveName(Inputs{Prefix: "SERVITOR", Name: "Release Candidate With A Very Long Name"}, test.limit)
			want := "servitor-" + truncate("release-candidate-with-a-very-long-name", test.limit-len("servitor")-1)
			if err != nil || name != want || len(name) != test.limit || !test.pattern.MatchString(name) {
				t.Fatalf("explicit prefixed name = %q, %v; want %q", name, err, want)
			}
		})
	}

	name, err = runner.resolveName(Inputs{Prefix: "ClassicPrefix"}, 35)
	if err != nil || name != "classicprefix-260907112913-ab12cd34" {
		t.Fatalf("long generated prefix = %q, %v", name, err)
	}

	for _, prefix := range []string{"---", "123-servitor"} {
		if _, err := runner.resolveName(Inputs{Prefix: prefix}, 32); err == nil {
			t.Fatalf("invalid prefix %q was accepted", prefix)
		}
	}
	if _, err := runner.resolveName(Inputs{Prefix: strings.Repeat("a", 11)}, 32); err == nil {
		t.Fatal("oversized generated prefix was accepted")
	}
	if _, err := runner.resolveName(Inputs{Prefix: strings.Repeat("a", 32), Name: "cluster"}, 32); err == nil {
		t.Fatal("prefix with no explicit-name room was accepted")
	}
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
	if got, want := fake.calls, [][]string{
		{"-chdir=" + workspace, "init", "-input=false", "-no-color"},
		{"-chdir=" + workspace, "plan", "-input=false", "-no-color", "-out=" + ictterraform.PlanName, "-var-file=" + filepath.Join(workspace, ictterraform.TFVarsName)},
		{"-chdir=" + workspace, "apply", "-input=false", "-no-color", ictterraform.PlanName},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Terraform calls = %#v, want %#v", got, want)
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

func TestPlanInitializesCOSBackendWithoutApplyingAndWritesStrictResult(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	resultPath := filepath.Join(t.TempDir(), "result.json")
	backend := ictterraform.BackendConfig{
		Version:                   1,
		Bucket:                    "ict-state-bucket",
		Key:                       "allocations/cluster-123.tfstate",
		Region:                    "us-south",
		Endpoint:                  "https://s3.us-south.cloud-object-storage.appdomain.cloud",
		SkipCredentialsValidation: true,
		SkipMetadataAPICheck:      true,
		SkipRegionValidation:      true,
		SkipRequestingAccountID:   true,
		ForcePathStyle:            true,
	}
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	runner.Now = func() time.Time { return time.Date(2026, 9, 8, 18, 34, 29, 0, time.UTC) }
	runner.Suffix = func() string { return "ab12cd34" }
	runner.Environ = []string{"AWS_ACCESS_KEY_ID=secret-id", "AWS_SECRET_ACCESS_KEY=secret-value"}
	inputs := configuredInputs(t)
	inputs.Name = ""
	inputs.Owner = "Servitor"

	if err := runner.Plan(context.Background(), inputs, backend, resultPath); err != nil {
		t.Fatal(err)
	}
	if got, want := fake.calls, [][]string{
		{
			"-chdir=" + workspace, "init", "-input=false", "-no-color",
			"-backend-config=bucket=ict-state-bucket",
			"-backend-config=key=allocations/cluster-123.tfstate",
			"-backend-config=region=us-south",
			"-backend-config=endpoint=https://s3.us-south.cloud-object-storage.appdomain.cloud",
			"-backend-config=skip_credentials_validation=true",
			"-backend-config=skip_metadata_api_check=true",
			"-backend-config=skip_region_validation=true",
			"-backend-config=skip_requesting_account_id=true",
			"-backend-config=force_path_style=true",
		},
		{"-chdir=" + workspace, "plan", "-input=false", "-no-color", "-out=" + ictterraform.PlanName, "-var-file=" + filepath.Join(workspace, ictterraform.TFVarsName)},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Terraform calls = %#v, want %#v", got, want)
	}
	if strings.Contains(strings.Join(actionNames(fake.calls), ","), "apply") {
		t.Fatalf("plan invoked apply: %#v", fake.calls)
	}
	if info, err := os.Stat(filepath.Join(workspace, ictterraform.PlanName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved plan = %v, %v", info, err)
	}
	if backendData, err := os.ReadFile(filepath.Join(workspace, "backend.tf")); err != nil || !strings.Contains(string(backendData), "backend \"s3\"") {
		t.Fatalf("backend declaration = %q, %v", backendData, err)
	}
	result, err := ReadPlanResult(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Values.ClusterName != "servitor-260908183429-ab12cd34" || result.PlanPath != filepath.Join(workspace, ictterraform.PlanName) || !reflect.DeepEqual(result.Backend, backend) {
		t.Fatalf("plan result = %#v", result)
	}
	resultData, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(resultData), "secret-value") || strings.Contains(string(resultData), "AWS_ACCESS_KEY_ID") {
		t.Fatalf("plan result contains credentials: %s", resultData)
	}
	if err := runner.Plan(context.Background(), inputs, backend, filepath.Join(t.TempDir(), "second.json")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate plan state ID error = %v", err)
	}
	if err := os.WriteFile(resultPath, append(resultData, []byte(`{"credential":"not-allowed"}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPlanResult(resultPath); err == nil {
		t.Fatal("result with trailing credential-like data was accepted")
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

func TestCreateConfirmStdinApprovalPaths(t *testing.T) {
	for _, test := range []struct {
		name      string
		input     string
		wantError string
		wantGone  bool
		wantApply bool
	}{
		{name: "piped literal yes", input: "yes\n", wantApply: true},
		{name: "piped decline", input: "Yes\n", wantGone: true},
		{name: "piped EOF", wantError: "read confirmation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "workspace")
			fake := &fakeTerraform{}
			runner := newRunner(workspace, fake)
			runner.Stdin = strings.NewReader(test.input)
			inputs := configuredInputs(t)
			inputs.ConfirmStdin = true

			err := runner.Create(context.Background(), inputs)
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v", err)
			}
			if test.wantError == "" && err != nil {
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
		})
	}
}

func TestExecRunnerCancellationGracefullyInterruptsTerraform(t *testing.T) {
	bin := t.TempDir()
	ready := filepath.Join(bin, "ready")
	interrupted := filepath.Join(bin, "interrupted")
	release := filepath.Join(bin, "release")
	terraform := filepath.Join(bin, "terraform")
	script := "#!/bin/sh\ntrap 'printf interrupt >> \"$INTERRUPTED\"; while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done; exit 0' INT\n: > \"$READY\"\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(terraform, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("PATH")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+path)
	t.Setenv("READY", ready)
	t.Setenv("INTERRUPTED", interrupted)
	t.Setenv("RELEASE", release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (ExecRunner{}).Run(ctx, os.Environ(), io.Discard, io.Discard, "terraform", "apply")
	}()
	waitForFile := func(path string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(path); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", path)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitForFile(ready)
	cancel()
	waitForFile(interrupted)
	select {
	case err := <-done:
		t.Fatalf("Terraform returned before its interrupt handler completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run error = %v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Terraform was not awaited after graceful interrupt")
	}
	data, err := os.ReadFile(interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "interrupt"); got != 1 {
		t.Fatalf("interrupt count = %d, want 1", got)
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

func TestCreatePreservesWorkspaceOnCanceledApply(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	fake := &fakeTerraform{applyErr: context.Canceled}
	runner := newRunner(workspace, fake)
	inputs := configuredInputs(t)
	inputs.AutoApprove = true
	if err := runner.Create(context.Background(), inputs); !errors.Is(err, context.Canceled) {
		t.Fatalf("create error = %v, want context cancellation", err)
	}
	if _, err := os.Stat(workspace); err != nil {
		t.Fatalf("canceled apply removed workspace: %v", err)
	}
	if got, want := strings.Join(actionNames(fake.calls), ","), "init,plan,apply"; got != want {
		t.Fatalf("actions = %q, want %q", got, want)
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
		if got, want := fake.calls, [][]string{
			{"-chdir=" + workspace, "init", "-input=false", "-no-color"},
			{"-chdir=" + workspace, "destroy", "-input=false", "-no-color", "-auto-approve", "-var-file=" + filepath.Join(workspace, ictterraform.TFVarsName)},
		}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Terraform calls = %#v, want %#v", got, want)
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
