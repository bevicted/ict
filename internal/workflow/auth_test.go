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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ictterraform "github.com/bevicted/ict/internal/terraform"
)

type authTerraform struct {
	calls             [][]string
	sensitiveCalls    [][]string
	tfvars            [][]byte
	outputs           map[string]string
	blockAuthApply    bool
	cleanupDestroyErr error
	workspaceForPlan  string
}

func (f *authTerraform) Run(ctx context.Context, _ []string, _ io.Writer, _ io.Writer, _ string, args ...string) error {
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
	if mode == "vpn" {
		inputs.AuthPolicy = AuthPolicy{AllocationUID: "allocation-123", VPNServerID: "vpn-1", SecretsManagerID: "sm-1", SecretsManagerRegion: "eu-gb", SecretGroupID: "group-1", CertificateTemplate: "client-template", Issuer: "issuer-1", TTL: "168h"}
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
	path := filepath.Join(t.TempDir(), "context.json")
	if err := runner.Plan(context.Background(), "allocation-123", inputs, backend, path); err != nil {
		t.Fatal(err)
	}
	return path
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
	fake := &authTerraform{outputs: map[string]string{"auth_mode": "unsupported"}}
	resultPath := filepath.Join(t.TempDir(), "apply-result.json")
	manifestPath := filepath.Join(t.TempDir(), "auth-manifest.json")
	outputDir := filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, resultPath, AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	assertOperationResult(t, resultPath, "apply", runner.Workspace)
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
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": vpn.Chain, "vpn_expiry": vpn.Expiry, "vpn_issuer": "issuer-1",
	}}
	manifestPath, outputDir := filepath.Join(t.TempDir(), "auth-manifest.json"), filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, filepath.Join(t.TempDir(), "apply-result.json"), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "available" || manifest.Mode != "vpn" || len(manifest.Artifacts) != 2 || manifest.Expiry != vpn.Expiry {
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
}

type syntheticCertificateFixture struct {
	CA          string
	Chain       string
	Certificate string
	Key         string
	Expiry      string
}

func syntheticCertificateMaterial(t *testing.T, usage x509.ExtKeyUsage, notBefore, notAfter time.Time) syntheticCertificateFixture {
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
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "synthetic-client"}, NotBefore: notBefore.UTC().Truncate(time.Second), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
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
		"auth_mode": "vpn", "private_endpoint": "https://api.private.example.invalid", "private_ca_certificate": admin.Chain, "private_admin_certificate": admin.Certificate, "private_admin_key": admin.Key, "vpn_profile": "client\nremote vpn.example.invalid 443\n<ca>\n" + vpn.CA + "</ca>", "vpn_certificate": vpn.Certificate, "vpn_private_key": vpn.Key, "vpn_ca_chain": "", "vpn_expiry": vpn.Expiry, "vpn_issuer": "issuer-1",
	}}
	manifestPath, outputDir := filepath.Join(t.TempDir(), "auth-manifest.json"), filepath.Join(t.TempDir(), "auth")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "apply"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Apply(context.Background(), "allocation-123", contextPath, backend, filepath.Join(t.TempDir(), "apply-result.json"), AuthExport{ManifestPath: manifestPath, OutputDir: outputDir}); err != nil {
		t.Fatal(err)
	}
	var manifest AuthManifest
	if err := json.Unmarshal(mustRead(t, manifestPath), &manifest); err != nil || manifest.Availability != "unavailable" || manifest.Reason != "vpn-certificate" {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	if entries, err := os.ReadDir(outputDir); err != nil || len(entries) != 0 {
		t.Fatalf("partial VPN export = %#v, %v", entries, err)
	}
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

func TestApplyMalformedAuthModeIsUnavailable(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpc")
	fake := &authTerraform{outputs: map[string]string{"auth_mode": "not-a-mode"}}
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
	if len(fake.calls) != 2 {
		t.Fatalf("public-only destroy unexpectedly invoked auth cleanup: %#v", fake.calls)
	}
}

func TestDestroyVPNAuthCleanupUsesFrozenCompanionStateWithoutAcquisition(t *testing.T) {
	backend := backendConfig()
	inputs := configuredInputs(t)
	inputs.AuthPolicy = AuthPolicy{AllocationUID: "allocation-123", VPNServerID: "vpn-1", SecretsManagerID: "sm-1", SecretsManagerRegion: "eu-gb", SecretGroupID: "group-1", CertificateTemplate: "client-template", Issuer: "issuer-1", TTL: "168h"}
	planWorkspace := filepath.Join(t.TempDir(), "plan")
	planFake := &authTerraform{workspaceForPlan: planWorkspace}
	contextPath := filepath.Join(t.TempDir(), "context.json")
	if err := (Runner{Workspace: planWorkspace, Terraform: planFake, Terminal: func() bool { return false }}).Plan(context.Background(), "allocation-123", inputs, backend, contextPath); err != nil {
		t.Fatal(err)
	}
	// Destroy must use the frozen context, not changed target defaults or auth inputs.
	if err := os.WriteFile(inputs.ConfigPath, []byte("broken: changed defaults\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs.AuthPolicy.SecretsManagerID = "changed-default"

	fake := &authTerraform{}
	resultPath := filepath.Join(t.TempDir(), "destroy-result.json")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "destroy"), Terraform: fake, Terminal: func() bool { return false }}
	if err := runner.Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 4 || !strings.Contains(strings.Join(fake.calls[2], " "), "key=allocations/cluster-123.tfstate.auth") || !slicesContains(fake.calls[3], "-refresh=false") {
		t.Fatalf("cleanup calls = %#v", fake.calls)
	}
	if len(fake.sensitiveCalls) != 0 || len(fake.tfvars) != 2 || strings.Contains(string(fake.tfvars[1]), "cluster_name") || !strings.Contains(string(fake.tfvars[1]), `"auth_secrets_manager_id":"sm-1"`) || strings.Contains(string(fake.tfvars[1]), "changed-default") {
		t.Fatalf("cleanup unexpectedly acquired auth or used mutable defaults: calls=%#v tfvars=%q", fake.sensitiveCalls, fake.tfvars)
	}
	assertOperationResult(t, resultPath, "destroy", runner.Workspace)
}

func TestDestroyVPNAuthCleanupMissingOrPartialStateAndStaleSecretAreBestEffort(t *testing.T) {
	for _, test := range []struct {
		name              string
		cleanupDestroyErr error
		wantCleanup       string
	}{
		{name: "missing companion state"},
		{name: "partial companion state"},
		{name: "provider stale secret 404", cleanupDestroyErr: errors.New("provider secret 404 synthetic detail"), wantCleanup: "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := backendConfig()
			contextPath := authContext(t, backend, "vpn")
			fake := &authTerraform{cleanupDestroyErr: test.cleanupDestroyErr}
			var stderr bytes.Buffer
			resultPath := filepath.Join(t.TempDir(), "destroy-result.json")
			runner := Runner{Workspace: filepath.Join(t.TempDir(), "destroy"), Terraform: fake, Terminal: func() bool { return false }, Stderr: &stderr}
			if err := runner.Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath); err != nil {
				t.Fatal(err)
			}
			if len(fake.calls) != 4 || !slicesContains(fake.calls[3], "-refresh=false") || len(fake.sensitiveCalls) != 0 {
				t.Fatalf("cleanup calls = %#v, sensitive output = %#v", fake.calls, fake.sensitiveCalls)
			}
			var result OperationResult
			if err := json.Unmarshal(mustRead(t, resultPath), &result); err != nil || result.AuthCleanup != test.wantCleanup {
				t.Fatalf("destroy result = %#v, %v", result, err)
			}
			if test.wantCleanup == "failed" {
				if stderr.String() != "ict: auth cleanup unavailable\n" || strings.Contains(stderr.String(), "404") {
					t.Fatalf("cleanup failure reporting = %q", stderr.String())
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("successful best-effort cleanup reported failure: %q", stderr.String())
			}
		})
	}
}

func TestDestroyVPNAuthCleanupHandlesProvider404WithControlledTerraformSubprocess(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "terraform.log")
	executable := filepath.Join(bin, "terraform")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$ICT_TERRAFORM_LOG\"\ncase \"$1:$2\" in *ict-auth-cleanup-*:destroy) printf 'provider stale secret 404 synthetic detail\\n' >&2; exit 1;; esac\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("ICT_TERRAFORM_LOG", logPath)
	var stderr bytes.Buffer
	resultPath := filepath.Join(t.TempDir(), "destroy-result.json")
	runner := Runner{Workspace: filepath.Join(t.TempDir(), "destroy"), Terminal: func() bool { return false }, Stderr: &stderr}
	if err := runner.Destroy(context.Background(), "allocation-123", contextPath, backend, resultPath); err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(mustRead(t, logPath)))
	joined := strings.Join(lines, " ")
	if len(lines) == 0 || !strings.Contains(joined, "key=allocations/cluster-123.tfstate.auth") || !strings.Contains(joined, "-refresh=false") || strings.Contains(joined, " apply ") || strings.Contains(joined, " output ") {
		t.Fatalf("controlled terraform calls = %q", joined)
	}
	var result OperationResult
	if err := json.Unmarshal(mustRead(t, resultPath), &result); err != nil || result.AuthCleanup != "failed" {
		t.Fatalf("destroy result = %#v, %v", result, err)
	}
	if stderr.String() != "ict: auth cleanup unavailable\n" || strings.Contains(stderr.String(), "404") {
		t.Fatalf("subprocess cleanup reporting = %q", stderr.String())
	}
}

func TestInfrastructureTFVarsExcludeFrozenAuthPolicy(t *testing.T) {
	policy := &AuthPolicy{AllocationUID: "allocation-123", VPNServerID: "vpn-1"}
	data, err := infrastructureTFVars(Values{ClusterName: "allocation-123", AuthPolicy: policy})
	if err != nil || strings.Contains(string(data), "auth_policy") {
		t.Fatalf("infrastructure tfvars = %s, %v", data, err)
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
