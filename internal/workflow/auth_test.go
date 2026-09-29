package workflow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

type authCertificateStore struct {
	metadata  map[string]CertificateMetadata
	deleted   []string
	getErr    error
	listErr   error
	deleteErr error
}

func (s *authCertificateStore) Get(_ context.Context, id string) (CertificateMetadata, error) {
	if s.getErr != nil {
		return CertificateMetadata{}, s.getErr
	}
	metadata, ok := s.metadata[id]
	if !ok {
		return CertificateMetadata{}, errCertificateNotFound
	}
	return metadata, nil
}

func (s *authCertificateStore) List(_ context.Context, _ string) ([]CertificateMetadata, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	result := make([]CertificateMetadata, 0, len(s.metadata))
	for _, metadata := range s.metadata {
		result = append(result, metadata)
	}
	return result, nil
}

func (s *authCertificateStore) Delete(_ context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.metadata, id)
	s.deleted = append(s.deleted, id)
	return nil
}

func ownedCertificateStore() *authCertificateStore {
	return &authCertificateStore{metadata: map[string]CertificateMetadata{"certificate-123": {ID: "certificate-123", AllocationUID: "allocation-123", AttemptID: "allocation-123"}}}
}

func authAttempt(id string) AuthAttempt {
	return AuthAttempt{AllocationUID: "allocation-123", AttemptID: id}
}

func testAuthTmpfsVerifier(path string, _, _ int64) (string, error) {
	return path, nil
}

func init() {
	defaultAuthTmpfsVerifier = testAuthTmpfsVerifier
}

type authTerraform struct {
	calls                 [][]string
	environments          [][]string
	sensitiveCalls        [][]string
	sensitiveEnvironments [][]string
	tfvars                [][]byte
	outputs               map[string]string
	blockAuthApply        bool
	cleanupDestroyErr     error
	workspaceForPlan      string
}

func (f *authTerraform) Run(ctx context.Context, environment []string, _ io.Writer, _ io.Writer, _ string, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	f.environments = append(f.environments, append([]string(nil), environment...))
	for _, arg := range args {
		if path, ok := strings.CutPrefix(arg, "-var-file="); ok {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			f.tfvars = append(f.tfvars, contents)
		}
	}
	if f.blockAuthApply && len(args) > 1 && args[1] == "apply" && strings.Contains(args[0], "ict-auth-") {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(args) > 1 && args[1] == "plan" {
		return os.WriteFile(filepath.Join(f.workspaceForPlan, ictterraform.PlanName), []byte("saved plan"), 0o600)
	}
	if len(args) > 1 && args[1] == "destroy" && strings.Contains(args[0], "ict-auth-cleanup-") {
		return f.cleanupDestroyErr
	}
	return nil
}

func (f *authTerraform) Output(context.Context, []string, string, ...string) ([]byte, error) {
	return nil, errors.New("unexpected ordinary Terraform output")
}

func (f *authTerraform) SensitiveOutput(_ context.Context, environment []string, _ string, args ...string) ([]byte, error) {
	f.sensitiveCalls = append(f.sensitiveCalls, append([]string(nil), args...))
	f.sensitiveEnvironments = append(f.sensitiveEnvironments, append([]string(nil), environment...))
	name := args[len(args)-1]
	value, ok := f.outputs[name]
	if !ok && name == "vpn_certificate_id" {
		value, ok = "certificate-123", true
	}
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
	if mode == "vpn" {
		inputs.AuthPolicy = AuthPolicy{VPNServerID: "vpn-1", SecretsManagerID: "sm-1", SecretsManagerRegion: "eu-gb", SecretGroupID: "group-1", CertificateTemplate: "client-template", Issuer: "issuer-1", TTL: "168h"}
	}
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
	planPath := filepath.Join(t.TempDir(), "plan-context.json")
	if err := runner.Plan(context.Background(), "allocation-123", inputs, backend, planPath); err != nil {
		t.Fatal(err)
	}
	plan, err := ReadPlanResult(planPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth-context.json")
	context := AuthContext{Version: 1, StateID: plan.StateID, Values: plan.Values, Recovery: AuthRecoveryContext{Endpoints: plan.Recovery.Endpoints, Values: plan.Recovery.Values, SatelliteSSHPublicKeyFingerprint: plan.Recovery.SatelliteSSHPublicKeyFingerprint, TFVarsSHA256: plan.Recovery.TFVarsSHA256}}
	if err := writeJSON(path, context); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuthAttemptRequiresSafeExplicitIdentity(t *testing.T) {
	if err := validateAuthAttempt(AuthAttempt{AllocationUID: "allocation-123", AttemptID: "auth-retry-456"}); err != nil {
		t.Fatalf("rejected independent safe attempt: %v", err)
	}
	for _, attempt := range []AuthAttempt{{AllocationUID: "allocation-123", AttemptID: ""}, {AllocationUID: "allocation-123", AttemptID: "../escape"}, {AllocationUID: "allocation-123", AttemptID: strings.Repeat("a", 129)}} {
		if err := validateAuthAttempt(attempt); err == nil {
			t.Fatalf("accepted unsafe attempt: %#v", attempt)
		}
	}
}

func TestAuthContextRejectsLegacyBackendBeforeBackendValidation(t *testing.T) {
	path := authContext(t, backendConfig(), "vpn")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	data = append(data[:len(data)-1], []byte(`,"backend":{"version":1,"bucket":"unused","key":"unused","region":"unused","endpoint":"https://unused.example.invalid"}}`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ReadAuthContext(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "backend"`) || strings.Contains(err.Error(), `invalid backend region "unused"`) {
		t.Fatalf("legacy placeholder backend error = %v", err)
	}
}

func TestAuthTmpfsVerifierRequiresBoundedCapacityContract(t *testing.T) {
	var gotMaximum, gotMinimum int64
	runner := Runner{AuthTmpfsVerifier: func(path string, maximum, minimum int64) (string, error) {
		gotMaximum, gotMinimum = maximum, minimum
		return path, nil
	}}
	if _, err := runner.validateAuthTmpfs(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if gotMaximum != 512<<20 || gotMinimum != 384<<20 {
		t.Fatalf("tmpfs contract = maximum %d minimum %d, want 512MiB and 384MiB", gotMaximum, gotMinimum)
	}
}

func TestApplyRendersPublicKubeconfigFromProviderCertificateOutputs(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode":                "public",
		"public_endpoint":          "https://api.public.example.invalid",
		"public_ca_certificate":    admin.Chain,
		"public_admin_certificate": admin.Certificate,
		"public_admin_key":         admin.Key,
	}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	persistentHome := filepath.Join(t.TempDir(), "persistent-home")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Environ: []string{
		"HOME=" + persistentHome,
		"XDG_CACHE_HOME=" + filepath.Join(persistentHome, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(persistentHome, "config"),
		"XDG_DATA_HOME=" + filepath.Join(persistentHome, "data"),
		"XDG_STATE_HOME=" + filepath.Join(persistentHome, "state"),
	}, Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "auth", "")
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
	if len(fake.calls) != 2 || !slicesContains(fake.calls[0], "-backend=false") || !slicesContains(fake.calls[1], "-backup=-") || strings.Contains(strings.Join(fake.calls[0], " "), "backend-config") {
		t.Fatalf("auth Terraform did not use local disposable state: %#v", fake.calls)
	}
	if !slicesContains(fake.calls[1], "-state="+strings.TrimPrefix(fake.calls[1][0], "-chdir=")+"/terraform.tfstate") {
		t.Fatalf("auth Terraform did not use a tmpfs-local state path: %#v", fake.calls[1])
	}
	workspace := strings.TrimPrefix(fake.calls[0][0], "-chdir=")
	for _, environment := range append(fake.environments, fake.sensitiveEnvironments...) {
		values := make(map[string]string, len(environment))
		for _, entry := range environment {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				t.Fatalf("invalid environment entry %q", entry)
			}
			values[key] = value
		}
		for key, directory := range map[string]string{
			"HOME":                "home",
			"TMPDIR":              "tmp",
			"TF_DATA_DIR":         "tf-data",
			"TF_PLUGIN_CACHE_DIR": "plugin-cache",
			"XDG_CACHE_HOME":      "cache",
			"XDG_CONFIG_HOME":     "config",
			"XDG_DATA_HOME":       "data",
			"XDG_STATE_HOME":      "state",
		} {
			if value := values[key]; value != filepath.Join(workspace, directory) {
				t.Fatalf("auth %s = %q, want %q", key, value, filepath.Join(workspace, directory))
			}
		}
		if values["TF_WORKSPACE"] != "default" {
			t.Fatalf("auth TF_WORKSPACE = %q", values["TF_WORKSPACE"])
		}
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("auth scratch workspace was not removed: %v", err)
	}
}

func TestApplyPrivateEndpointSkipsKubeconfigRetrieval(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{outputs: map[string]string{"auth_mode": "unsupported"}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "auth", "")
	if len(fake.sensitiveCalls) != 1 || fake.sensitiveCalls[0][len(fake.sensitiveCalls[0])-1] != "auth_mode" {
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

func TestApplyVPNRendersCompleteBundle(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": vpn.Chain, "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	manifestPath, outputDir := filepath.Join(t.TempDir(), "auth-manifest.json"), filepath.Join(t.TempDir(), "auth")
	result, err := ReadAuthContext(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	stateID := "run-state-456"
	result.StateID = stateID
	if err := writeJSON(contextPath, result); err != nil {
		t.Fatal(err)
	}
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	attempt := AuthAttempt{AllocationUID: "allocation-123", AttemptID: "auth-retry-1710000000"}
	if err := runner.AuthWithAttempt(context.Background(), stateID, contextPath, filepath.Join(t.TempDir(), "auth-result.json"), t.TempDir(), attempt, AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "available" || manifest.Mode != "vpn" || len(manifest.Artifacts) != 2 || manifest.Expiry != vpn.Expiry || manifest.Certificate == nil || manifest.Certificate.AllocationUID != attempt.AllocationUID || manifest.Certificate.AttemptID != attempt.AttemptID {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	for _, name := range []string{"kubeconfig.yaml", "client.ovpn"} {
		info, err := os.Stat(filepath.Join(outputDir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private artifact %s = %v, %v", name, info, err)
		}
	}
	if profile := string(mustRead(t, filepath.Join(outputDir, "client.ovpn"))); !strings.Contains(profile, "<cert>") || !strings.Contains(profile, "<key>") || strings.Contains(profile, "auth-user-pass") {
		t.Fatalf("profile was not self-contained: %q", profile)
	}
	if output := fake.sensitiveCalls[len(fake.sensitiveCalls)-1]; output[len(output)-1] != "vpn_certificate_authority" {
		t.Fatalf("VPN authority output = %#v", output)
	}
	var variables map[string]any
	if err := json.Unmarshal(fake.tfvars[0], &variables); err != nil || variables["auth_attempt_id"] != attempt.AttemptID {
		t.Fatalf("auth tfvars did not retain explicit attempt: %#v, %v", variables, err)
	}
}

func TestAuthExportReuseClearsKnownArtifactsOnly(t *testing.T) {
	backend := backendConfig()
	vpnContext := authContext(t, backend, "vpn")
	publicContext := authContext(t, backend, "vpc")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": vpn.Chain, "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	outputDir := filepath.Join(t.TempDir(), "auth")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	runner := Runner{Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", vpnContext, filepath.Join(t.TempDir(), "vpn-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(outputDir, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.outputs = map[string]string{
		"auth_mode": "public", "public_endpoint": "https://api.public.example.invalid", "public_ca_certificate": admin.Chain, "public_admin_certificate": admin.Certificate, "public_admin_key": admin.Key,
	}
	if err := runner.Auth(context.Background(), "allocation-123", publicContext, filepath.Join(t.TempDir(), "public-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "client.ovpn")); !os.IsNotExist(err) {
		t.Fatalf("reused public auth retained VPN profile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "kubeconfig.yaml")); err != nil {
		t.Fatalf("reused public auth did not write kubeconfig: %v", err)
	}
	fake.outputs = map[string]string{"auth_mode": "not-a-mode"}
	if err := runner.Auth(context.Background(), "allocation-123", publicContext, filepath.Join(t.TempDir(), "unavailable-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kubeconfig.yaml", "client.ovpn"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); !os.IsNotExist(err) {
			t.Fatalf("unavailable auth retained %s: %v", name, err)
		}
	}
	if contents := string(mustRead(t, marker)); contents != "keep" {
		t.Fatalf("unrelated output file changed: %q", contents)
	}
}

func TestAuthManifestWriteFailureBlocksResultAndCleansArtifacts(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "public", "public_endpoint": "https://api.public.example.invalid", "public_ca_certificate": admin.Chain, "public_admin_certificate": admin.Certificate, "public_admin_key": admin.Key,
	}}
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	resultPath := filepath.Join(t.TempDir(), "auth-result.json")
	manifestFailure := errors.New("simulated manifest failure")
	runner := Runner{
		Terraform: fake,
		Terminal:  func() bool { return false },
		AuthManifestWriter: func(path string, manifest AuthManifest) error {
			if manifest.Availability == "available" {
				return manifestFailure
			}
			return writeAuthManifest(path, manifest)
		},
	}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); !errors.Is(err, manifestFailure) {
		t.Fatalf("auth error = %v, want manifest persistence error", err)
	}
	if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
		t.Fatalf("auth wrote successful operation result: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "kubeconfig.yaml")); !os.IsNotExist(err) {
		t.Fatalf("manifest failure retained kubeconfig: %v", err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.Reason != "manifest-write" {
		t.Fatalf("fallback manifest = %#v, %v", manifest, err)
	}
}

func TestAuthExportLockRejectsConcurrentAndStaleCalls(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "public", "public_endpoint": "https://api.public.example.invalid", "public_ca_certificate": admin.Chain, "public_admin_certificate": admin.Certificate, "public_admin_key": admin.Key,
	}}
	outputDir := filepath.Join(t.TempDir(), "auth")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	entered := make(chan struct{})
	resume := make(chan struct{})
	runner := Runner{
		Terraform: fake,
		Terminal:  func() bool { return false },
		AuthManifestWriter: func(path string, manifest AuthManifest) error {
			if manifest.Availability == "available" {
				close(entered)
				<-resume
			}
			return writeAuthManifest(path, manifest)
		},
	}
	first := make(chan error, 1)
	go func() {
		first <- runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "first-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first auth export did not reach manifest write")
	}
	artifact := mustRead(t, filepath.Join(outputDir, "kubeconfig.yaml"))
	calls := len(fake.sensitiveCalls)
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "second-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); !errors.Is(err, errAuthOutputLocked) {
		t.Fatalf("concurrent auth error = %v, want output lock error", err)
	}
	if got := mustRead(t, filepath.Join(outputDir, "kubeconfig.yaml")); !bytes.Equal(got, artifact) || len(fake.sensitiveCalls) != calls {
		t.Fatalf("concurrent auth touched artifacts or invoked Terraform: calls=%d, want %d", len(fake.sensitiveCalls), calls)
	}
	close(resume)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, authOutputLockName)); !os.IsNotExist(err) {
		t.Fatalf("auth output lock remains after return: %v", err)
	}

	staleOutputDir := filepath.Join(t.TempDir(), "stale-auth")
	if err := os.MkdirAll(staleOutputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	staleArtifact := filepath.Join(staleOutputDir, "kubeconfig.yaml")
	if err := os.WriteFile(staleArtifact, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleOutputDir, authOutputLockName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	calls = len(fake.sensitiveCalls)
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "stale-result.json"), t.TempDir(), AuthExport{ManifestPath: filepath.Join(t.TempDir(), "stale-manifest.json"), OutputDir: staleOutputDir}); !errors.Is(err, errAuthOutputLocked) {
		t.Fatalf("stale lock auth error = %v, want output lock error", err)
	}
	if got := string(mustRead(t, staleArtifact)); got != "unchanged" || len(fake.sensitiveCalls) != calls {
		t.Fatalf("stale lock touched artifacts or invoked Terraform: artifact=%q calls=%d, want %d", got, len(fake.sensitiveCalls), calls)
	}
}

func TestAvailableManifestFailureReturnsRedactedPublicCompensationErrors(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "public", "public_endpoint": "https://api.public.example.invalid", "public_ca_certificate": admin.Chain, "public_admin_certificate": admin.Certificate, "public_admin_key": admin.Key,
	}}
	availableFailure := errors.New("available-manifest-private-detail")
	unavailableFailure := errors.New("unavailable-manifest-private-detail")
	outputDir := filepath.Join(t.TempDir(), "auth")
	resultPath := filepath.Join(t.TempDir(), "auth-result.json")
	runner := Runner{
		Terraform: fake,
		Terminal:  func() bool { return false },
		AuthManifestWriter: func(_ string, manifest AuthManifest) error {
			if manifest.Availability == "available" {
				if err := os.Remove(filepath.Join(outputDir, "kubeconfig.yaml")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(outputDir, "kubeconfig.yaml"), 0o700); err != nil {
					t.Fatal(err)
				}
				return availableFailure
			}
			return unavailableFailure
		},
	}
	err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: filepath.Join(t.TempDir(), "auth-manifest.json"), OutputDir: outputDir})
	if !errors.Is(err, availableFailure) || !errors.Is(err, unavailableFailure) {
		t.Fatalf("public compensation error = %v", err)
	}
	if message := err.Error(); !strings.Contains(message, "auth export artifact removal failed") || strings.Contains(message, "private-detail") {
		t.Fatalf("public compensation error is not redacted and joined: %q", message)
	}
	if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
		t.Fatalf("public compensation wrote successful operation result: %v", err)
	}
}

func TestVPNManifestWriteFailureCleansCertificateAndRecordsPendingReference(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": vpn.Chain, "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	store := ownedCertificateStore()
	store.deleteErr = errors.New("transport failure")
	manifestFailure := errors.New("simulated manifest failure")
	runner := Runner{
		Terraform:    fake,
		Certificates: store,
		Terminal:     func() bool { return false },
		AuthManifestWriter: func(path string, manifest AuthManifest) error {
			if manifest.Availability == "available" {
				return manifestFailure
			}
			return writeAuthManifest(path, manifest)
		},
	}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "auth-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); !errors.Is(err, manifestFailure) {
		t.Fatalf("auth error = %v, want manifest persistence error", err)
	}
	for _, name := range []string{"kubeconfig.yaml", "client.ovpn"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); !os.IsNotExist(err) {
			t.Fatalf("manifest failure retained %s: %v", name, err)
		}
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.CleanupOutcome != cleanupOutcomePending || manifest.Certificate == nil || manifest.Certificate.ID != "certificate-123" {
		t.Fatalf("fallback VPN manifest = %#v, %v", manifest, err)
	}
}

func TestAvailableManifestFailureReturnsRedactedVPNCompensationErrors(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": vpn.Chain, "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	availableFailure := errors.New("available-manifest-private-detail")
	unavailableFailure := errors.New("unavailable-manifest-private-detail")
	outputDir := filepath.Join(t.TempDir(), "auth")
	store := ownedCertificateStore()
	store.deleteErr = errors.New("certificate-cleanup-private-detail")
	runner := Runner{
		Terraform:    fake,
		Certificates: store,
		Terminal:     func() bool { return false },
		AuthManifestWriter: func(_ string, manifest AuthManifest) error {
			if manifest.Availability == "available" {
				for _, name := range []string{"kubeconfig.yaml", "client.ovpn"} {
					if err := os.Remove(filepath.Join(outputDir, name)); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Mkdir(filepath.Join(outputDir, "kubeconfig.yaml"), 0o700); err != nil {
					t.Fatal(err)
				}
				return availableFailure
			}
			return unavailableFailure
		},
	}
	resultPath := filepath.Join(t.TempDir(), "auth-result.json")
	err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: filepath.Join(t.TempDir(), "auth-manifest.json"), OutputDir: outputDir})
	if !errors.Is(err, availableFailure) || !errors.Is(err, unavailableFailure) {
		t.Fatalf("VPN compensation error = %v", err)
	}
	if message := err.Error(); !strings.Contains(message, "auth export artifact removal failed") || !strings.Contains(message, "auth export certificate cleanup failed") || strings.Contains(message, "private-detail") {
		t.Fatalf("VPN compensation error is not redacted and joined: %q", message)
	}
	if len(store.deleted) != 0 || store.metadata["certificate-123"].ID == "" {
		t.Fatalf("VPN compensation did not preserve pending certificate cleanup: deleted=%#v remaining=%#v", store.deleted, store.metadata)
	}
	if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
		t.Fatalf("VPN compensation wrote successful operation result: %v", err)
	}
}

func TestAuthExportRejectsNonRegularKnownArtifact(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	outputDir := filepath.Join(t.TempDir(), "auth")
	if err := os.MkdirAll(filepath.Join(outputDir, "kubeconfig.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	fake := &authTerraform{outputs: map[string]string{"auth_mode": "unsupported"}}
	runner := Runner{Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "auth-result.json"), t.TempDir(), AuthExport{ManifestPath: filepath.Join(t.TempDir(), "auth-manifest.json"), OutputDir: outputDir}); err == nil {
		t.Fatal("accepted non-regular auth artifact")
	}
	if info, err := os.Stat(filepath.Join(outputDir, "kubeconfig.yaml")); err != nil || !info.IsDir() {
		t.Fatalf("non-regular artifact was altered: %v, %v", info, err)
	}
	if len(fake.calls) != 0 || len(fake.sensitiveCalls) != 0 {
		t.Fatalf("unsafe export invoked Terraform: %#v, %#v", fake.calls, fake.sensitiveCalls)
	}
}

type syntheticCertificateFixture struct {
	CA          string
	Chain       string
	Certificate string
	Key         string
	Expiry      string
}

func syntheticCertificateMaterial(t *testing.T, usage x509.ExtKeyUsage, notBefore, notAfter time.Time) syntheticCertificateFixture {
	return syntheticCertificateMaterialWithUsages(t, []x509.ExtKeyUsage{usage}, notBefore, notAfter)
}

func syntheticCertificateMaterialWithUsages(t *testing.T, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time) syntheticCertificateFixture {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter = notAfter.UTC().Truncate(time.Second)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "synthetic-client"}, NotBefore: notBefore.UTC().Truncate(time.Second), NotAfter: notAfter, ExtKeyUsage: usages, KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &key.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	intermediatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}))
	return syntheticCertificateFixture{CA: rootPEM, Chain: intermediatePEM + rootPEM, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), Expiry: notAfter.Format(time.RFC3339)}
}

func TestApplyVPNRejectsPartialMaterialWithoutArtifacts(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": "", "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	manifestPath, outputDir := filepath.Join(t.TempDir(), "auth-manifest.json"), filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Certificates: ownedCertificateStore(), Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "auth-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.Reason != string(vpnCertificateChainParseReason) {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	if entries, err := os.ReadDir(outputDir); err != nil || len(entries) != 0 {
		t.Fatalf("partial VPN export = %#v, %v", entries, err)
	}
}

func TestApplyVPNCertificateReportsValueFreeSubreasons(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	valid := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	unrelated := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	dualUsage := syntheticCertificateMaterialWithUsages(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	outputs := func() map[string]string {
		return map[string]string{
			"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key,
			"vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + valid.CA + "</ca>", "vpn_certificate": valid.Certificate, "vpn_private_key": valid.Key, "vpn_ca_chain": valid.Chain, "vpn_expiry": valid.Expiry, "vpn_certificate_authority": "issuer-1",
		}
	}
	tests := []struct {
		name   string
		reason string
		mutate func(map[string]string)
	}{
		{"client-only chain", "", func(map[string]string) {}},
		{"intermediate-terminated client chain", "", func(values map[string]string) { values["vpn_ca_chain"] = certificatePEM(t, valid.Chain, 0) }},
		{"leaf parse", string(vpnCertificateLeafParseReason), func(values map[string]string) { values["vpn_certificate"] = "not-a-certificate-private-value" }},
		{"leaf usage", string(vpnCertificateLeafUsageReason), func(values map[string]string) {
			expired := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
			values["vpn_certificate"], values["vpn_private_key"], values["vpn_ca_chain"], values["vpn_expiry"] = expired.Certificate, expired.Key, expired.Chain, expired.Expiry
		}},
		{"key parse", string(vpnCertificateKeyParseReason), func(values map[string]string) { values["vpn_private_key"] = "not-a-private-key" }},
		{"key mismatch", string(vpnCertificateKeyMismatchReason), func(values map[string]string) { values["vpn_private_key"] = unrelated.Key }},
		{"chain parse", string(vpnCertificateChainParseReason), func(values map[string]string) { values["vpn_ca_chain"] = "not-a-certificate-chain" }},
		{"chain authority", string(vpnCertificateChainAuthorityReason), func(values map[string]string) { values["vpn_ca_chain"] = valid.Certificate }},
		{"out-of-order chain", string(vpnCertificateChainVerifyReason), func(values map[string]string) {
			values["vpn_ca_chain"] = certificatePEM(t, valid.Chain, 1) + certificatePEM(t, valid.Chain, 0)
		}},
		{"unrelated chain", string(vpnCertificateChainVerifyReason), func(values map[string]string) { values["vpn_ca_chain"] = certificatePEM(t, unrelated.Chain, 0) }},
		{"broken chain", string(vpnCertificateChainVerifyReason), func(values map[string]string) {
			values["vpn_ca_chain"] = certificatePEM(t, valid.Chain, 0) + certificatePEM(t, unrelated.Chain, 1)
		}},
		{"server EKU", string(vpnCertificateServerEKUReason), func(values map[string]string) {
			values["vpn_certificate"], values["vpn_private_key"], values["vpn_ca_chain"], values["vpn_expiry"] = dualUsage.Certificate, dualUsage.Key, dualUsage.Chain, dualUsage.Expiry
		}},
		{"expiry mismatch", string(vpnCertificateExpiryMismatchReason), func(values map[string]string) {
			values["vpn_expiry"] = time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
		}},
		{"certificate authority mismatch", string(vpnCertificateAuthorityMismatchReason), func(values map[string]string) { values["vpn_certificate_authority"] = "unexpected-authority" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &authTerraform{outputs: outputs()}
			test.mutate(fake.outputs)
			manifestPath, outputDir := filepath.Join(t.TempDir(), "auth-manifest.json"), filepath.Join(t.TempDir(), "auth")
			runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Certificates: ownedCertificateStore(), Terminal: func() bool { return false }}
			if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "apply-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
				t.Fatal(err)
			}
			data := mustRead(t, manifestPath)
			var manifest AuthManifest
			if err := json.Unmarshal(data, &manifest); err != nil || manifest.Reason != test.reason {
				t.Fatalf("manifest = %#v, %v", manifest, err)
			}
			if test.reason == "" && manifest.Availability != "available" {
				t.Fatalf("client-only chain was unavailable: %#v", manifest)
			}
			if test.reason != "" && (manifest.Availability != "unavailable" || strings.Contains(string(data), "private-value")) {
				t.Fatalf("unsafe failure manifest = %q", data)
			}
		})
	}
}

func certificatePEM(t *testing.T, value string, index int) string {
	t.Helper()
	var blocks []string
	for rest := []byte(value); len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			t.Fatal("invalid certificate fixture")
		}
		blocks = append(blocks, string(pem.EncodeToMemory(block)))
		rest = remaining
	}
	if index >= len(blocks) {
		t.Fatal("certificate fixture is incomplete")
	}
	return blocks[index]
}

func TestRenderVPNProfileRejectsExternalCredentialsAndExecution(t *testing.T) {
	tests := []struct {
		name      string
		directive string
	}{
		{"auth user pass", "auth-user-pass"},
		{"HTTP proxy user pass", "http-proxy-user-pass /tmp/proxy-login"},
		{"askpass", "askpass /tmp/passphrase"},
		{"script security", "script-security 2"},
		{"DNS up down", "dns-updown /tmp/script"},
		{"up", "up /tmp/script"},
		{"down", "down /tmp/script"},
		{"route up", "route-up /tmp/script"},
		{"route pre down", "route-pre-down /tmp/script"},
		{"IP change", "ipchange /tmp/script"},
		{"TLS verify", "tls-verify /tmp/script"},
		{"auth user pass verify", "auth-user-pass-verify /tmp/script via-env"},
		{"client connect", "client-connect /tmp/script"},
		{"client disconnect", "client-disconnect /tmp/script"},
		{"learn address", "learn-address /tmp/script"},
		{"client challenge response", "client-crresponse /tmp/script"},
		{"plugin", "plugin /tmp/plugin"},
		{"management", "management /tmp/socket unix"},
		{"PKCS12", "pkcs12 /tmp/client.p12"},
		{"certificate", "cert /tmp/cert.pem"},
		{"key", "key /tmp/key.pem"},
		{"CA", "ca /tmp/ca.pem"},
		{"secret", "secret /tmp/static.key"},
		{"TLS auth", "tls-auth /tmp/auth.key"},
		{"TLS crypt", "tls-crypt /tmp/crypt.key"},
		{"TLS crypt v2", "tls-crypt-v2 /tmp/crypt-v2.key"},
		{"HTTP proxy credential file", "http-proxy proxy.example.invalid 8080 /tmp/proxy-login"},
		{"SOCKS proxy credential file", "socks-proxy proxy.example.invalid 1080 /tmp/proxy-login"},
		{"SOCKS proxy missing port", "socks-proxy proxy.example.invalid /tmp/proxy-login"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, directive := range []string{test.directive, strings.ToUpper(test.directive), " \t" + strings.ToUpper(test.directive) + " \t"} {
				profile := "client\nremote vpn.example.invalid 443\n<ca>\ntrust\n</ca>\n" + directive
				if _, err := renderVPNProfile(profile, "certificate", "key", ""); err == nil {
					t.Fatalf("accepted unsafe directive %q", directive)
				}
			}
		})
	}
}

func TestRenderVPNProfileRejectsUnsafeInlineBlocks(t *testing.T) {
	trust := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)).CA
	base := "client\nremote vpn.example.invalid 443\n<ca>\n" + trust + "</ca>\n"
	tests := []struct {
		name    string
		profile string
	}{
		{"inline login credentials", base + "<auth-user-pass>\nusername\npassword\n</auth-user-pass>"},
		{"inline plugin", base + "<plugin>\nplugin.so\n</plugin>"},
		{"inline external key", base + "<key>\nprivate-key\n</key>"},
		{"unknown block", base + "<unknown>\nvalue\n</unknown>"},
		{"unclosed block", base + "<tls-crypt>\ninline-key"},
		{"mismatched close", base + "<tls-crypt>\ninline-key\n</tls-auth>"},
		{"nested block", "client\nremote vpn.example.invalid 443\n<ca>\n" + trust + "<tls-auth>\ninline-key\n</tls-auth>\n</ca>"},
		{"duplicate block", base + "<ca>\n" + trust + "</ca>"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := renderVPNProfile(test.profile, "certificate", "key", ""); err == nil {
				t.Fatal("accepted unsafe inline block")
			}
		})
	}
}

func TestRenderVPNProfileRequiresActiveValidRemote(t *testing.T) {
	trust := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)).CA
	ca := "<ca>\n" + trust + "</ca>"
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"comment-only", "client\n  # remote ignored.example.invalid 443 udp\n\t; remote ignored.example.invalid 443 udp\n" + ca, true},
		{"missing host", "client\nremote # no host\n" + ca, true},
		{"malformed host", "client\nremote -vpn.example.invalid 443 udp\n" + ca, true},
		{"invalid port", "client\nremote vpn.example.invalid 0 udp\n" + ca, true},
		{"invalid protocol", "client\nremote vpn.example.invalid 443 not-a-protocol\n" + ca, true},
		{"remote inside inline block", "client\n<tls-auth>\nremote hidden.example.invalid 443 udp\n</tls-auth>\n" + ca, true},
		{"multiple active remotes", "client\nremote primary.example.invalid 443 udp # preferred\nremote fallback.example.invalid. 1194 tcp-client\n" + ca, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rendered, err := renderVPNProfile(test.profile, "certificate", "key", "")
			if (err != nil) != test.wantErr {
				t.Fatalf("renderVPNProfile() error = %v", err)
			}
			if !test.wantErr && (!strings.Contains(string(rendered), "remote primary.example.invalid 443 udp") || !strings.Contains(string(rendered), "remote fallback.example.invalid. 1194 tcp-client")) {
				t.Fatalf("rendered profile did not preserve remotes: %q", rendered)
			}
		})
	}
}

func TestRenderVPNProfileAllowsSafeInlineDirectives(t *testing.T) {
	trust := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)).CA
	base := "client\nremote vpn.example.invalid 443\npersist-key\npersist-tun\nkey-direction 1\n<ca>\n" + trust + "</ca>"
	tests := []struct {
		name     string
		profile  string
		expected string
	}{
		{"CA", base, "<ca>"},
		{"TLS auth", base + "\n<tls-auth>\ninline-key\n</tls-auth>", "<tls-auth>\ninline-key\n</tls-auth>"},
		{"TLS crypt", base + "\n<tls-crypt>\ninline-key\n</tls-crypt>", "<tls-crypt>\ninline-key\n</tls-crypt>"},
		{"TLS crypt v2", base + "\n<tls-crypt-v2>\ninline-key\n</tls-crypt-v2>", "<tls-crypt-v2>\ninline-key\n</tls-crypt-v2>"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rendered, err := renderVPNProfile(test.profile, "certificate", "key", "")
			if err != nil || !strings.Contains(string(rendered), test.expected) {
				t.Fatalf("rendered profile = %q, %v", rendered, err)
			}
		})
	}
	for _, directive := range []string{"http-proxy proxy.example.invalid 8080", "socks-proxy proxy.example.invalid 1080"} {
		t.Run(directive, func(t *testing.T) {
			if _, err := renderVPNProfile(base+"\n"+directive, "certificate", "key", ""); err != nil {
				t.Fatalf("rejected proxy without credential file: %v", err)
			}
		})
	}
}

func TestRenderVPNProfileNormalizesQuotedProfile(t *testing.T) {
	trust := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)).CA
	profile := strconv.Quote("client\nremote vpn.example.invalid 443\n<ca>\n" + trust + "</ca>")
	rendered, err := renderVPNProfile(profile, "certificate", "key", "")
	if err != nil || !strings.Contains(string(rendered), "remote vpn.example.invalid 443") {
		t.Fatalf("quoted profile = %q, %v", rendered, err)
	}
}

func TestCertificateValidationRejectsInvalidSyntheticMaterial(t *testing.T) {
	valid := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	unrelated := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	expired := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	notYetValid := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
	wrongUsage := syntheticCertificateMaterial(t, x509.ExtKeyUsageServerAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	dualUsage := syntheticCertificateMaterialWithUsages(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	tests := []struct {
		name        string
		certificate string
		key         string
		chain       string
		expiry      string
	}{
		{"valid chain", valid.Certificate, valid.Key, valid.Chain, valid.Expiry},
		{"malformed certificate PEM", "not a certificate", valid.Key, valid.Chain, valid.Expiry},
		{"malformed key PEM", valid.Certificate, "not a private key", valid.Chain, valid.Expiry},
		{"mismatched key", valid.Certificate, unrelated.Key, valid.Chain, valid.Expiry},
		{"unrelated chain", valid.Certificate, valid.Key, unrelated.Chain, valid.Expiry},
		{"expired certificate", expired.Certificate, expired.Key, expired.Chain, expired.Expiry},
		{"not yet valid certificate", notYetValid.Certificate, notYetValid.Key, notYetValid.Chain, notYetValid.Expiry},
		{"wrong extended key usage", wrongUsage.Certificate, wrongUsage.Key, wrongUsage.Chain, wrongUsage.Expiry},
		{"dual extended key usage", dualUsage.Certificate, dualUsage.Key, dualUsage.Chain, dualUsage.Expiry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateVPNCertificate(test.certificate, test.key, test.chain, test.expiry)
			if (err == nil) != (test.name == "valid chain") {
				t.Fatalf("validateVPNCertificate() error = %v", err)
			}
		})
	}
}

func TestRenderKubeconfigRejectsUnrelatedAdminMaterial(t *testing.T) {
	valid := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	unrelated := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if _, err := renderKubeconfig("https://api.private.example.invalid", valid.Chain, valid.Certificate, valid.Key); err != nil {
		t.Fatalf("valid admin material rejected: %v", err)
	}
	for _, test := range []struct {
		name, ca, certificate, key string
	}{
		{"malformed CA", "not a certificate", valid.Certificate, valid.Key},
		{"unrelated CA", unrelated.Chain, valid.Certificate, valid.Key},
		{"mismatched admin key", valid.Chain, valid.Certificate, unrelated.Key},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := renderKubeconfig("https://api.private.example.invalid", test.ca, test.certificate, test.key); err == nil {
				t.Fatal("invalid admin material accepted")
			}
		})
	}
}

func TestRenderVPNProfileRejectsNonCertificateTrust(t *testing.T) {
	if _, err := renderVPNProfile("client\nremote vpn.example.invalid 443\n<ca>\narbitrary trust\n</ca>", "certificate", "key", ""); err == nil {
		t.Fatal("accepted non-certificate VPN trust")
	}
}

func TestRenderVPNProfileRejectsIntermediateOnlyTrust(t *testing.T) {
	material := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	intermediate := certificatePEM(t, material.Chain, 0)
	profile := "client\nremote vpn.example.invalid 443\n<ca>\n" + intermediate + "</ca>"
	if _, err := renderVPNProfile(profile, material.Certificate, material.Key, material.Chain); err == nil {
		t.Fatal("accepted intermediate-only VPN profile trust")
	}
}

func TestApplyMalformedAuthModeIsUnavailable(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{outputs: map[string]string{"auth_mode": "not-a-mode"}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "auth", "")
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || len(manifest.Artifacts) != 0 {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	if len(fake.sensitiveCalls) != 1 || fake.sensitiveCalls[0][len(fake.sensitiveCalls[0])-1] != "auth_mode" {
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
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "auth", "")
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
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, resultPath, t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: filepath.Join(t.TempDir(), "auth")}); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 || len(fake.sensitiveCalls) != 0 {
		t.Fatalf("unsupported Satellite invoked auth Terraform: %#v, %#v", fake.calls, fake.sensitiveCalls)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unsupported" {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
}

func TestDestroyDoesNotInferAuthCleanupOwnership(t *testing.T) {
	backend := backendConfig()
	contextPath := writePlanContext(t, backend)
	fake := &authTerraform{}
	workspace := filepath.Join(t.TempDir(), "destroy")
	resultPath := filepath.Join(t.TempDir(), "destroy-result.json")
	runner := Runner{Workspace: workspace, Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("public-only destroy unexpectedly invoked auth cleanup: %#v", fake.calls)
	}
}

func TestCertificateErrorsExposeOnlyHTTPClass(t *testing.T) {
	for _, test := range []struct {
		status int
		want   string
	}{{http.StatusUnauthorized, cleanupReasonAuthentication}, {http.StatusTooManyRequests, cleanupReasonRateLimit}, {http.StatusServiceUnavailable, cleanupReasonService}, {http.StatusBadRequest, cleanupReasonRequest}} {
		err := mapCertificateError(&core.DetailedResponse{StatusCode: test.status}, errors.New("https://secrets.example.invalid/id/secret-123"))
		var apiErr certificateAPIError
		if !errors.As(err, &apiErr) || apiErr.reason != test.want || strings.Contains(err.Error(), "secret-123") {
			t.Fatalf("status %d error = %v, reason = %#v", test.status, err, apiErr)
		}
	}
}

func TestAuthCleanupDeletesOnlyCurrentAttemptCertificates(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	contextResult, err := ReadAuthContext(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	contextResult.StateID = "run-state-456"
	if err := writeJSON(contextPath, contextResult); err != nil {
		t.Fatal(err)
	}
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{
		"certificate-123":   {ID: "certificate-123", AllocationUID: "allocation-123", AttemptID: "attempt-123"},
		"certificate-race":  {ID: "certificate-race", AllocationUID: "allocation-123", AttemptID: "attempt-123"},
		"certificate-retry": {ID: "certificate-retry", AllocationUID: "allocation-123", AttemptID: "attempt-124"},
		"certificate-other": {ID: "certificate-other", AllocationUID: "other-allocation", AttemptID: "attempt-123"},
	}}
	fake := &authTerraform{}
	resultPath := filepath.Join(t.TempDir(), "auth-cleanup-result.json")
	runner := Runner{Terraform: fake, Certificates: store, Terminal: func() bool { return false }}
	if err := runner.AuthCleanup(context.Background(), "run-state-456", contextPath, resultPath, []string{"certificate-123"}, "allocation-123", "attempt-123"); err != nil {
		t.Fatal(err)
	}
	var result OperationResult
	if err := json.Unmarshal(mustRead(t, resultPath), &result); err != nil || result.Operation != "auth-cleanup" || result.AuthCleanup != "cleaned" || result.Reason != "" || result.Certificate != nil {
		t.Fatalf("cleanup result = %#v, %v", result, err)
	}
	if len(fake.calls) != 0 || len(store.deleted) != 2 || store.metadata["certificate-retry"].ID == "" || store.metadata["certificate-other"].ID == "" {
		t.Fatalf("cleanup was not attempt-safe: calls=%#v deleted=%#v remaining=%#v", fake.calls, store.deleted, store.metadata)
	}
}

func TestAuthCleanupWithoutAttemptReconcilesEveryExplicitReferenceBeforeIncompleteList(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{
		"certificate-123": {ID: "certificate-123", AllocationUID: "allocation-123", AttemptID: "attempt-123"},
		"certificate-124": {ID: "certificate-124", AllocationUID: "allocation-123", AttemptID: "attempt-124"},
	}, listErr: errors.New("incomplete list")}
	resultPath := filepath.Join(t.TempDir(), "auth-cleanup-result.json")
	runner := Runner{Certificates: store, Terminal: func() bool { return false }}
	if err := runner.AuthCleanup(context.Background(), "allocation-123", contextPath, resultPath, []string{"certificate-123", "certificate-124"}, "allocation-123", ""); err != nil {
		t.Fatal(err)
	}
	if len(store.deleted) != 2 || store.metadata["certificate-123"].ID != "" || store.metadata["certificate-124"].ID != "" {
		t.Fatalf("explicit refs were not reconciled: deleted=%#v remaining=%#v", store.deleted, store.metadata)
	}
}

func TestAuthCleanupRejectsMismatchedCertificate(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{"certificate-123": {ID: "certificate-123", AllocationUID: "other-allocation", AttemptID: "attempt-123"}}}
	resultPath := filepath.Join(t.TempDir(), "auth-cleanup-result.json")
	runner := Runner{Certificates: store, Terminal: func() bool { return false }}
	if err := runner.AuthCleanup(context.Background(), "allocation-123", contextPath, resultPath, []string{"certificate-123"}, "allocation-123", ""); err != nil {
		t.Fatal(err)
	}
	var result OperationResult
	if err := json.Unmarshal(mustRead(t, resultPath), &result); err != nil || result.AuthCleanup != cleanupOutcomePending || result.CleanupOutcome != cleanupOutcomePending || result.CleanupReason != cleanupReasonOwnershipMismatch || len(store.deleted) != 0 {
		t.Fatalf("mismatched cleanup result = %#v, %v; deleted=%#v", result, err, store.deleted)
	}
}

func TestAuthCleanupRecordsPendingCertificateReference(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{}, getErr: errors.New("transport failure")}
	resultPath := filepath.Join(t.TempDir(), "auth-cleanup-result.json")
	runner := Runner{Certificates: store, Terminal: func() bool { return false }}
	if err := runner.AuthCleanup(context.Background(), "allocation-123", contextPath, resultPath, []string{"certificate-123"}, "allocation-123", ""); err != nil {
		t.Fatal(err)
	}
	var result OperationResult
	if err := json.Unmarshal(mustRead(t, resultPath), &result); err != nil || result.AuthCleanup != cleanupOutcomePending || result.CleanupOutcome != cleanupOutcomePending || result.CleanupReason != cleanupReasonUnknown || result.Certificate == nil || result.Certificate.ID != "certificate-123" {
		t.Fatalf("pending cleanup result = %#v, %v", result, err)
	}
}

func TestAuthCleanupRecordsPendingOwnershipWithoutCertificateID(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{}, listErr: errors.New("transport failure")}
	resultPath := filepath.Join(t.TempDir(), "auth-cleanup-result.json")
	runner := Runner{Certificates: store, Terminal: func() bool { return false }}
	if err := runner.AuthCleanup(context.Background(), "allocation-123", contextPath, resultPath, nil, "allocation-123", ""); err != nil {
		t.Fatal(err)
	}
	var result OperationResult
	if err := json.Unmarshal(mustRead(t, resultPath), &result); err != nil || result.AuthCleanup != "pending" || result.Certificate != nil {
		t.Fatalf("ownership-only cleanup result = %#v, %v", result, err)
	}
}

func TestVPNFailureCleansOnlyCurrentAttemptCertificateBeforeTmpfsWipe(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": "not-a-chain", "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{
		"certificate-123":        {ID: "certificate-123", AllocationUID: "allocation-123", AttemptID: "attempt-123"},
		"certificate-concurrent": {ID: "certificate-concurrent", AllocationUID: "allocation-123", AttemptID: "attempt-124"},
	}}
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	runner := Runner{Terraform: fake, Certificates: store, Terminal: func() bool { return false }}
	if err := runner.AuthWithAttempt(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "auth-result.json"), t.TempDir(), authAttempt("attempt-123"), AuthExport{ManifestPath: manifestPath, OutputDir: filepath.Join(t.TempDir(), "auth")}); err != nil {
		t.Fatal(err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.Reason != string(vpnCertificateChainParseReason) || manifest.Certificate != nil || len(store.deleted) != 1 || store.metadata["certificate-concurrent"].ID == "" {
		t.Fatalf("failed VPN cleanup = %#v, %v; deleted=%#v remaining=%#v", manifest, err, store.deleted, store.metadata)
	}
}

func TestVPNFailureReportsPendingCertificateReference(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	admin := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vpn := syntheticCertificateMaterial(t, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fake := &authTerraform{outputs: map[string]string{
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": "not-a-chain", "vpn_expiry": vpn.Expiry, "vpn_certificate_authority": "issuer-1",
	}}
	store := ownedCertificateStore()
	store.deleteErr = errors.New("transport failure")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	runner := Runner{Terraform: fake, Certificates: store, Terminal: func() bool { return false }}
	if err := runner.Auth(context.Background(), "allocation-123", contextPath, filepath.Join(t.TempDir(), "auth-result.json"), t.TempDir(), AuthExport{ManifestPath: manifestPath, OutputDir: filepath.Join(t.TempDir(), "auth")}); err != nil {
		t.Fatal(err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.Reason != string(vpnCertificateChainParseReason) || manifest.CleanupOutcome != cleanupOutcomePending || manifest.CleanupReason != cleanupReasonDelete || manifest.Certificate == nil || manifest.Certificate.ID != "certificate-123" {
		t.Fatalf("pending failed VPN cleanup = %#v, %v", manifest, err)
	}
}

func TestInfrastructureTFVarsExposeOnlyFrozenVPNServerID(t *testing.T) {
	policy := &AuthPolicy{VPNServerID: "vpn-1", SecretsManagerID: "secrets-1", SecretsManagerRegion: "us-south", SecretGroupID: "group-1", CertificateTemplate: "template-1", Issuer: "issuer-1", TTL: "2h"}
	data, err := infrastructureTFVars(Values{ClusterName: "allocation-123", AuthPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	var variables map[string]any
	if err := json.Unmarshal(data, &variables); err != nil {
		t.Fatal(err)
	}
	if variables["auth_vpn_server_id"] != "vpn-1" || strings.Contains(string(data), "auth_policy") || strings.Contains(string(data), "secrets-1") || strings.Contains(string(data), "template-1") {
		t.Fatalf("infrastructure tfvars = %s", data)
	}
}

func TestAuthTFVarsUsesSeparateAttempts(t *testing.T) {
	data, err := authTFVars(Values{
		ClusterName:       "allocation-123",
		ClusterMode:       "vpc",
		ResourceGroupName: "test-group",
		Region:            "test-region",
	}, AuthAttempt{AllocationUID: "allocation-123", AttemptID: "apply-allocation-123"}, "/tmp/config")
	if err != nil {
		t.Fatal(err)
	}
	var variables map[string]any
	if err := json.Unmarshal(data, &variables); err != nil {
		t.Fatal(err)
	}
	if variables["cluster_mode"] != "vpc" || variables["auth_allocation_uid"] != "allocation-123" || variables["auth_attempt_id"] != "apply-allocation-123" {
		t.Fatalf("auth variables = %#v", variables)
	}
	retry, err := authTFVars(Values{ClusterName: "allocation-123", ClusterMode: "vpc", ResourceGroupName: "test-group", Region: "test-region"}, AuthAttempt{AllocationUID: "allocation-123", AttemptID: "auth-retry-1710000000"}, "/tmp/config")
	if err != nil {
		t.Fatal(err)
	}
	var retryVariables map[string]any
	if err := json.Unmarshal(retry, &retryVariables); err != nil || retryVariables["auth_attempt_id"] != "auth-retry-1710000000" || retryVariables["auth_attempt_id"] == variables["auth_attempt_id"] {
		t.Fatalf("retry auth variables = %#v, %v", retryVariables, err)
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
