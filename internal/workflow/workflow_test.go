package workflow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bevicted/ict/internal/prompt"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

type fakeTerraform struct {
	resources bool
	calls     [][]string
	environs  [][]string
}

type fakeIBMCloud struct {
	environs [][]string
}

func (f *fakeIBMCloud) Run(_ context.Context, environ []string, _ string, args ...string) ([]byte, error) {
	f.environs = append(f.environs, append([]string(nil), environ...))
	switch args[0] {
	case "resource":
		return []byte(`[{"name":"fixture-group"}]`), nil
	case "ks":
		switch args[1] {
		case "locations":
			return []byte(`[{"name":"us-south-1"}]`), nil
		case "versions":
			return []byte(`[{"version":"1.31.9"}]`), nil
		case "flavor":
			return []byte(`[{"name":"bx2.2x8"}]`), nil
		}
	}
	return nil, errors.New("unexpected discovery command")
}

func (f *fakeTerraform) Run(_ context.Context, environ []string, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	f.environs = append(f.environs, append([]string(nil), environ...))
	if len(args) >= 2 && args[len(args)-2] == "state" && args[len(args)-1] == "list" {
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
	return Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }, Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }, Suffix: func() string { return "deadbeef" }}
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
	for _, path := range []string{filepath.Join(workspace, "main.tf"), filepath.Join(workspace, "cluster-name.tftest.hcl"), filepath.Join(workspace, ictterraform.TFVarsName), filepath.Join(workspace, ictterraform.ContextName)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private runtime file %s = %v, %v", path, info, err)
		}
	}
	contextBytes, err := os.ReadFile(filepath.Join(workspace, ictterraform.ContextName))
	if err != nil || !strings.Contains(string(contextBytes), "override-vpc.example.invalid") {
		t.Fatalf("recovery context = %q, %v", contextBytes, err)
	}
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
	if len(fake.calls) != 1 || !strings.HasSuffix(strings.Join(fake.calls[0], " "), "state list") {
		t.Fatalf("mismatched create calls = %#v", fake.calls)
	}
	fake.calls = nil
	if err := runner.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.calls[len(fake.calls)-1], " "); !strings.Contains(got, "destroy -input=false -auto-approve") {
		t.Fatalf("destroy did not run: %q", got)
	}
}

func TestDestroyRefusesEmptyState(t *testing.T) {
	workspace := t.TempDir()
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "no saved context") {
		t.Fatalf("destroy without context = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, ".cluster"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ictterraform.ContextName), []byte(`{"version":1,"target":"example","endpoints":{},"values":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ictterraform.TFVarsName), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "state has no managed resources") {
		t.Fatalf("empty state destroy = %v", err)
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
	inputs.Target, inputs.Provider, inputs.Platform, inputs.Version, inputs.ResourceGroup, inputs.Zone, inputs.Flavor = "", "", "", "", "", "", ""
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
