package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ictterraform "github.com/bevicted/ict/internal/terraform"
)

type authTerraform struct {
	calls            [][]string
	sensitiveCalls   [][]string
	outputs          map[string]string
	blockAuthApply   bool
	workspaceForPlan string
}

func (f *authTerraform) Run(ctx context.Context, _ []string, _ io.Writer, _ io.Writer, _ string, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	if f.blockAuthApply && len(args) > 1 && args[1] == "apply" && strings.Contains(args[0], "ict-auth-") {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(args) > 1 && args[1] == "plan" {
		return os.WriteFile(filepath.Join(f.workspaceForPlan, ictterraform.PlanName), []byte("saved plan"), 0o600)
	}
	return nil
}

func (f *authTerraform) Output(context.Context, []string, string, ...string) ([]byte, error) {
	return nil, errors.New("unexpected ordinary Terraform output")
}

func (f *authTerraform) SensitiveOutput(_ context.Context, _ []string, _ string, args ...string) ([]byte, error) {
	f.sensitiveCalls = append(f.sensitiveCalls, append([]string(nil), args...))
	value, ok := f.outputs[args[len(args)-1]]
	if !ok {
		return nil, errors.New("missing sensitive output")
	}
	return []byte(value + "\n"), nil
}

func authContext(t *testing.T, backend ictterraform.BackendConfig, mode string) string {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "plan")
	fake := &authTerraform{workspaceForPlan: workspace}
	runner := Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }}
	inputs := configuredInputs(t)
	if mode == "satellite" {
		satelliteConfig := strings.Replace(testConfig, "providers: [vpc-gen2]", "providers: [satellite]", 1) + "      satellite: https://satellite.example.invalid\n      satellite_config: https://satellite-config.example.invalid\n"
		if err := os.WriteFile(inputs.ConfigPath, []byte(satelliteConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		inputs.Provider = "satellite"
		inputs.Platform = "openshift"
		inputs.Version = "4.18_openshift"
		inputs.SatelliteZones = []string{"us-south-1", "us-south-2", "us-south-3"}
		inputs.SatelliteManagedFrom = "synthetic-location"
		inputs.SatelliteHostImage = "synthetic-image"
		inputs.SatelliteHostProfile = "bx2-4x16"
		inputs.SatelliteSSHKeyID = "synthetic-key"
		inputs.SatelliteWorkerOperatingSystem = "RHCOS"
		inputs.WorkerCount = 3
	}
	path := filepath.Join(t.TempDir(), "context.json")
	if err := runner.Plan(context.Background(), "allocation-123", inputs, backend, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyRendersPublicKubeconfigFromProviderCertificateOutputs(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{outputs: map[string]string{
		"public_available":         "true",
		"public_endpoint":          "https://api.public.example.invalid",
		"public_ca_certificate":    "synthetic-ca",
		"public_admin_certificate": "synthetic-certificate",
		"public_admin_key":         "synthetic-private-key",
	}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, resultPath, AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "apply", runner.Workspace)
	data := mustRead(t, manifestPath)
	var manifest AuthManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 1 || manifest.Availability != "available" || manifest.Reason != "" || len(manifest.Artifacts) != 1 || manifest.Artifacts[0].Name != "kubeconfig.yaml" || strings.Contains(string(data), "synthetic-private-key") {
		t.Fatalf("manifest = %s", data)
	}
	exported := filepath.Join(outputDir, "kubeconfig.yaml")
	info, err := os.Stat(exported)
	contents := string(mustRead(t, exported))
	if err != nil || info.Mode().Perm() != 0o600 || validateKubeconfig([]byte(contents), "https://api.public.example.invalid") != nil || strings.Contains(contents, "certificate-authority:") || strings.Contains(contents, "client-certificate:") || strings.Contains(contents, "client-key:") {
		t.Fatalf("exported kubeconfig is not self-contained: %v, %v", info, err)
	}
	if len(fake.sensitiveCalls) != 5 || fake.sensitiveCalls[4][len(fake.sensitiveCalls[4])-1] != "public_admin_key" {
		t.Fatalf("sensitive calls = %#v", fake.sensitiveCalls)
	}
	if !strings.Contains(strings.Join(fake.calls[2], " "), "key=allocations/cluster-123.tfstate.auth") {
		t.Fatalf("auth init did not use companion state: %#v", fake.calls[2])
	}
}

func TestApplyPrivateEndpointSkipsKubeconfigRetrieval(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{outputs: map[string]string{"public_available": "false"}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, resultPath, AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "apply", runner.Workspace)
	if len(fake.sensitiveCalls) != 1 || fake.sensitiveCalls[0][len(fake.sensitiveCalls[0])-1] != "public_available" {
		t.Fatalf("private endpoint attempted credential retrieval: %#v", fake.sensitiveCalls)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "kubeconfig.yaml")); !os.IsNotExist(err) {
		t.Fatalf("private endpoint wrote a kubeconfig: %v", err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unsupported" {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
}

func TestApplyMalformedPublicAvailabilityIsUnavailable(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{outputs: map[string]string{"public_available": "not-a-boolean"}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, resultPath, AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "apply", runner.Workspace)
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || len(manifest.Artifacts) != 0 {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	if len(fake.sensitiveCalls) != 1 || fake.sensitiveCalls[0][len(fake.sensitiveCalls[0])-1] != "public_available" {
		t.Fatalf("malformed availability retrieved credentials: %#v", fake.sensitiveCalls)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "kubeconfig.yaml")); !os.IsNotExist(err) {
		t.Fatalf("malformed availability wrote a kubeconfig: %v", err)
	}
}

func TestValidateKubeconfigRejectsAccountCredentials(t *testing.T) {
	const endpoint = "https://api.public.example.invalid"
	contents := "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: Y2E=\n    server: " + endpoint + "\nusers:\n- name: admin\n  user:\n    client-certificate-data: Y2VydA==\n    client-key-data: cHJpdmF0ZS1rZXk=\n"
	for _, credential := range []string{"auth-provider:", "apiKey:", "api-key:", "api_key:", "ibm_api_key:"} {
		t.Run(credential, func(t *testing.T) {
			if err := validateKubeconfig([]byte(contents+"    "+credential+" synthetic-account-credential\n"), endpoint); err == nil {
				t.Fatal("account credential was accepted")
			}
		})
	}
}

func TestApplyAuthFailurePreservesInfrastructureSuccess(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{blockAuthApply: true}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	var stderr bytes.Buffer
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }, AuthTimeout: time.Millisecond, Stderr: &stderr}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, resultPath, AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "apply", runner.Workspace)
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.Reason != "terraform-apply" || len(manifest.Artifacts) != 0 {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	if stderr.String() != "ict: public auth unavailable: terraform-apply\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outputDir, "kubeconfig.yaml")); !os.IsNotExist(err) {
		t.Fatalf("failed export wrote an artifact: %v", err)
	}
}

func TestApplySatelliteAuthIsUnsupportedWithoutAuthTerraform(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "satellite")
	fake := &authTerraform{}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, resultPath, AuthExport{ManifestPath: manifestPath, OutputDir: filepath.Join(t.TempDir(), "auth")}); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || len(fake.sensitiveCalls) != 0 {
		t.Fatalf("unsupported Satellite invoked auth Terraform: %#v, %#v", fake.calls, fake.sensitiveCalls)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unsupported" {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
}

func TestDestroyAuthCleanupIsBestEffortAndUsesCompanionState(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{}
	workspace := filepath.Join(t.TempDir(), "destroy")
	resultPath := filepath.Join(t.TempDir(), "destroy-result.json")
	runner := Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 4 || !strings.Contains(strings.Join(fake.calls[2], " "), "key=allocations/cluster-123.tfstate.auth") || !slicesContains(fake.calls[3], "-refresh=false") {
		t.Fatalf("cleanup calls = %#v", fake.calls)
	}
}

func TestAuthTFVarsSelectsClusterProvider(t *testing.T) {
	data, err := authTFVars(Values{
		ClusterName:       "allocation-123",
		ClusterMode:       "vpc",
		ResourceGroupName: "test-group",
		Region:            "test-region",
	}, "/tmp/config")
	if err != nil {
		t.Fatal(err)
	}
	var variables map[string]any
	if err := json.Unmarshal(data, &variables); err != nil {
		t.Fatal(err)
	}
	if variables["cluster_mode"] != "vpc" {
		t.Fatalf("cluster_mode = %v", variables["cluster_mode"])
	}
}

func slicesContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
