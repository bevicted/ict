package workflow

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bevicted/ict/internal/config"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

const (
	defaultAuthTimeout = 5 * time.Minute
	maxAuthOutputBytes = 64 * 1024
	maxAuthManifest    = 4 * 1024
)

// AuthExport identifies private artifact and safe-manifest destinations. Supplying
// neither path disables the optional auth phase.
type AuthExport struct {
	ManifestPath string
	OutputDir    string
}

// AuthManifest is the bounded non-secret handoff for an optional auth export.
type AuthManifest struct {
	Version      int            `json:"version"`
	Availability string         `json:"availability"`
	Reason       string         `json:"reason,omitempty"`
	Artifacts    []AuthArtifact `json:"artifacts,omitempty"`
	Mode         string         `json:"mode,omitempty"`
	Expiry       string         `json:"expiry,omitempty"`
}

// AuthArtifact describes a private artifact without serializing its contents.
type AuthArtifact struct {
	Name string `json:"name"`
}

// SensitiveCommandRunner captures a credential-adjacent command result without
// writing either stream to ordinary task logs.
type SensitiveCommandRunner interface {
	SensitiveOutput(context.Context, []string, string, ...string) ([]byte, error)
}

// SensitiveOutput runs a Terraform command with bounded, non-logging capture.
func (ExecRunner) SensitiveOutput(ctx context.Context, environ []string, command string, args ...string) ([]byte, error) {
	cmd, err := terraformCommand(ctx, environ, command, args...)
	if err != nil {
		return nil, err
	}
	stdout := &boundedOutput{limit: maxAuthOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || stdout.truncated {
		return nil, errors.New("sensitive Terraform command failed")
	}
	return stdout.bytes, nil
}

type boundedOutput struct {
	bytes     []byte
	limit     int
	truncated bool
}

func (w *boundedOutput) Write(value []byte) (int, error) {
	remaining := w.limit - len(w.bytes)
	if remaining <= 0 {
		w.truncated = true
		return len(value), nil
	}
	if len(value) > remaining {
		w.bytes = append(w.bytes, value[:remaining]...)
		w.truncated = true
		return len(value), nil
	}
	w.bytes = append(w.bytes, value...)
	return len(value), nil
}

func (r Runner) authTimeout() time.Duration {
	if r.AuthTimeout > 0 {
		return r.AuthTimeout
	}
	return defaultAuthTimeout
}

func (r Runner) authEnvironment(endpoints config.Endpoints) []string {
	environment := r.environment(config.ResolvedTarget{Target: config.Target{Endpoints: endpoints}}.Environment())
	values := make(map[string]string, len(environment)+3)
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	values["TF_LOG"] = "OFF"
	values["TF_LOG_CORE"] = "OFF"
	values["TF_LOG_PROVIDER"] = "OFF"
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(values))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func (r Runner) sensitiveTerraform() SensitiveCommandRunner {
	if runner, ok := r.terraform().(SensitiveCommandRunner); ok {
		return runner
	}
	return ExecRunner{}
}

func validateAuthExport(export AuthExport) error {
	if export.ManifestPath == "" && export.OutputDir == "" {
		return nil
	}
	if export.ManifestPath == "" || export.OutputDir == "" {
		return errors.New("auth manifest file and auth output directory must be supplied together")
	}
	if err := ictterraform.ValidateResultPath(export.ManifestPath); err != nil {
		return fmt.Errorf("validate auth manifest path: %w", err)
	}
	if err := ictterraform.ValidateResultPath(export.OutputDir); err != nil {
		return fmt.Errorf("validate auth output directory: %w", err)
	}
	return nil
}

func (r Runner) exportAuth(ctx context.Context, result PlanResult, export AuthExport) {
	if export.ManifestPath == "" {
		return
	}
	manifest := AuthManifest{Version: 1, Availability: "unavailable"}
	if result.Values.ClusterMode == "satellite" {
		manifest.Availability = "unsupported"
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	if err := os.MkdirAll(export.OutputDir, 0o700); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "output-directory")
		return
	}
	authCtx, cancel := context.WithTimeout(ctx, r.authTimeout())
	defer cancel()
	workspace, err := os.MkdirTemp("", "ict-auth-")
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "workspace")
		return
	}
	defer os.RemoveAll(workspace)
	if err := os.Chmod(workspace, 0o700); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "workspace-permissions")
		return
	}
	if err := r.materializeAuth(workspace); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "assets")
		return
	}
	configDir := filepath.Join(workspace, "credentials")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "credentials-directory")
		return
	}
	tfvars, err := authTFVars(result.Values, configDir)
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "variables")
		return
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvars); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "variables-write")
		return
	}
	if err := ictterraform.MaterializeBackend(workspace); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "backend")
		return
	}
	backend := authBackend(result.Backend)
	environment := r.authEnvironment(result.Recovery.Endpoints)
	initArgs := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, backend.InitArgs()...)
	if err := r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", initArgs...); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "terraform-init")
		return
	}
	if err := r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", "-chdir="+workspace, "apply", "-input=false", "-no-color", "-auto-approve", "-var-file="+tfvarsPath); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "terraform-apply")
		return
	}
	mode, err := r.authOutput(authCtx, environment, workspace, "auth_mode")
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "auth-mode")
		return
	}
	switch mode {
	case "public":
		manifest.Mode = "public"
	case "vpn":
		if result.Values.AuthPolicy == nil {
			r.unavailableAuth(export.ManifestPath, manifest, "private-policy")
			return
		}
		r.exportVPNAuth(authCtx, environment, workspace, export, manifest, *result.Values.AuthPolicy)
		return
	case "unsupported":
		manifest.Availability = "unsupported"
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	default:
		r.unavailableAuth(export.ManifestPath, manifest, "auth-mode")
		return
	}
	endpoint, err := r.authOutput(authCtx, environment, workspace, "public_endpoint")
	if err != nil || endpoint == "" {
		r.unavailableAuth(export.ManifestPath, manifest, "public-endpoint")
		return
	}
	ca, err := r.authOutput(authCtx, environment, workspace, "public_ca_certificate")
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "admin-material")
		return
	}
	certificate, err := r.authOutput(authCtx, environment, workspace, "public_admin_certificate")
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "admin-material")
		return
	}
	key, err := r.authOutput(authCtx, environment, workspace, "public_admin_key")
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "admin-material")
		return
	}
	contents, err := renderKubeconfig(endpoint, ca, certificate, key)
	if err != nil || validateKubeconfig(contents, endpoint) != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "kubeconfig-render")
		return
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "kubeconfig.yaml"), contents); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "kubeconfig-write")
		return
	}
	manifest.Availability = "available"
	manifest.Artifacts = []AuthArtifact{{Name: "kubeconfig.yaml"}}
	_ = writeAuthManifest(export.ManifestPath, manifest)
}

func (r Runner) exportVPNAuth(ctx context.Context, environ []string, workspace string, export AuthExport, manifest AuthManifest, policy AuthPolicy) {
	endpoint, err := r.authOutput(ctx, environ, workspace, "private_endpoint")
	if err != nil || endpoint == "" {
		r.unavailableAuth(export.ManifestPath, manifest, "private-endpoint")
		return
	}
	outputs := make(map[string]string, 9)
	for _, name := range []string{"private_ca_certificate", "private_admin_certificate", "private_admin_key", "vpn_profile", "vpn_certificate", "vpn_private_key", "vpn_ca_chain", "vpn_expiry", "vpn_issuer"} {
		outputs[name], err = r.authOutput(ctx, environ, workspace, name)
		if err != nil {
			r.unavailableAuth(export.ManifestPath, manifest, "private-material")
			return
		}
	}
	kubeconfig, err := renderKubeconfig(endpoint, outputs["private_ca_certificate"], outputs["private_admin_certificate"], outputs["private_admin_key"])
	if err != nil || validateKubeconfig(kubeconfig, endpoint) != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "kubeconfig-render")
		return
	}
	expiry, err := validateVPNCertificate(outputs["vpn_certificate"], outputs["vpn_private_key"], outputs["vpn_ca_chain"], outputs["vpn_expiry"])
	if err != nil || outputs["vpn_issuer"] != policy.Issuer {
		r.unavailableAuth(export.ManifestPath, manifest, "vpn-certificate")
		return
	}
	profile, err := renderVPNProfile(outputs["vpn_profile"], outputs["vpn_certificate"], outputs["vpn_private_key"], outputs["vpn_ca_chain"])
	if err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "vpn-profile")
		return
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "kubeconfig.yaml"), kubeconfig); err != nil {
		r.unavailableAuth(export.ManifestPath, manifest, "kubeconfig-write")
		return
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "client.ovpn"), profile); err != nil {
		_ = os.Remove(filepath.Join(export.OutputDir, "kubeconfig.yaml"))
		r.unavailableAuth(export.ManifestPath, manifest, "vpn-write")
		return
	}
	manifest.Availability = "available"
	manifest.Mode = "vpn"
	manifest.Expiry = expiry.Format(time.RFC3339)
	manifest.Artifacts = []AuthArtifact{{Name: "kubeconfig.yaml"}, {Name: "client.ovpn"}}
	_ = writeAuthManifest(export.ManifestPath, manifest)
}

type certificateChain struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

func validateVPNCertificate(certificatePEM, keyPEM, chainPEM, reportedExpiry string) (time.Time, error) {
	certificate, err := validateCertificateAndKey(certificatePEM, keyPEM, chainPEM, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid VPN certificate: %w", err)
	}
	reported, err := time.Parse(time.RFC3339, reportedExpiry)
	if err != nil || !reported.Equal(certificate.NotAfter.UTC()) {
		return time.Time{}, errors.New("VPN expiry does not match certificate")
	}
	return certificate.NotAfter.UTC(), nil
}

func validateKubeconfigMaterial(caPEM, certificatePEM, keyPEM string) error {
	_, err := validateCertificateAndKey(certificatePEM, keyPEM, caPEM, x509.ExtKeyUsageClientAuth)
	return err
}

func validateCertificateAndKey(certificatePEM, keyPEM, chainPEM string, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	certificates, err := parseCertificates(certificatePEM)
	if err != nil || len(certificates) != 1 {
		return nil, errors.New("invalid leaf certificate")
	}
	certificate := certificates[0]
	now := time.Now()
	if !certificateValidAt(certificate, now) || certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !containsUsage(certificate.ExtKeyUsage, usage) {
		return nil, errors.New("invalid leaf certificate usage")
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(key.Public(), certificate.PublicKey) {
		return nil, errors.New("certificate and private key do not match")
	}
	chain, err := parseCertificateChain(chainPEM, now)
	if err != nil {
		return nil, err
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: chain.roots, Intermediates: chain.intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	return certificate, nil
}

func parseCertificateChain(value string, now time.Time) (certificateChain, error) {
	certificates, err := parseCertificates(value)
	if err != nil || len(certificates) == 0 {
		return certificateChain{}, errors.New("invalid certificate chain")
	}
	chain := certificateChain{roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	roots := 0
	for _, certificate := range certificates {
		if !certificateValidAt(certificate, now) || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return certificateChain{}, errors.New("invalid certificate authority")
		}
		if certificate.CheckSignatureFrom(certificate) == nil {
			chain.roots.AddCert(certificate)
			roots++
		} else {
			chain.intermediates.AddCert(certificate)
		}
	}
	if roots == 0 {
		return certificateChain{}, errors.New("certificate chain has no trust root")
	}
	for _, certificate := range certificates {
		if certificate.CheckSignatureFrom(certificate) == nil {
			continue
		}
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: chain.roots, Intermediates: chain.intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return certificateChain{}, fmt.Errorf("certificate authority chain verification failed: %w", err)
		}
	}
	return chain, nil
}

func parseCertificates(value string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for rest := []byte(value); ; {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		rest = remaining
		if len(strings.TrimSpace(string(rest))) == 0 {
			return certificates, nil
		}
	}
}

func parsePrivateKey(value string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("invalid private key PEM")
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key")
	}
	return signer, nil
}

func certificateValidAt(certificate *x509.Certificate, now time.Time) bool {
	return !now.Before(certificate.NotBefore) && now.Before(certificate.NotAfter)
}

func containsUsage(values []x509.ExtKeyUsage, wanted x509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	comparable, ok := left.(interface{ Equal(crypto.PublicKey) bool })
	return ok && comparable.Equal(right)
}

func renderVPNProfile(profile, certificate, key, chain string) ([]byte, error) {
	profile, err := normalizeVPNProfile(profile)
	if err != nil {
		return nil, err
	}
	blocks, err := parseVPNInlineBlocks(profile)
	if err != nil {
		return nil, err
	}
	if err := validateVPNDirectives(profile); err != nil {
		return nil, err
	}
	if _, err := profileTrustChain(blocks); err != nil {
		return nil, errors.New("invalid VPN profile trust")
	}
	certificate = strings.TrimSpace(certificate)
	chain = strings.TrimSpace(chain)
	if chain != "" {
		certificate += "\n" + chain
	}
	return []byte(profile + "\n<cert>\n" + certificate + "\n</cert>\n<key>\n" + strings.TrimSpace(key) + "\n</key>\n"), nil
}

func parseVPNInlineBlocks(profile string) (map[string]string, error) {
	allowed := map[string]bool{"ca": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true}
	blocks := make(map[string]string)
	var content strings.Builder
	var current string

	for _, line := range strings.Split(profile, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "<") {
			if current != "" {
				content.WriteString(line)
				content.WriteByte('\n')
			}
			continue
		}
		if !strings.HasSuffix(trimmed, ">") {
			return nil, errors.New("malformed VPN profile inline block")
		}
		name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "<"), ">")
		closing := strings.HasPrefix(name, "/")
		if closing {
			name = strings.TrimPrefix(name, "/")
		}
		name = strings.ToLower(name)
		if name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return nil, errors.New("malformed VPN profile inline block")
		}
		if closing {
			if current == "" || name != current {
				return nil, errors.New("malformed VPN profile inline block")
			}
			value := strings.TrimSpace(content.String())
			if value == "" {
				return nil, errors.New("malformed VPN profile inline block")
			}
			blocks[name] = value
			current = ""
			continue
		}
		if current != "" || !allowed[name] || blocks[name] != "" {
			return nil, errors.New("unsafe VPN profile inline block")
		}
		current = name
		content.Reset()
	}
	if current != "" {
		return nil, errors.New("malformed VPN profile inline block")
	}
	return blocks, nil
}

func normalizeVPNProfile(profile string) (string, error) {
	profile = strings.TrimSpace(profile)
	if strings.HasPrefix(profile, "\"") {
		decoded, err := strconv.Unquote(profile)
		if err != nil {
			return "", errors.New("invalid encoded VPN profile")
		}
		profile = decoded
	}
	return profile, nil
}

func validateVPNDirectives(profile string) error {
	var block string
	remoteFound := false
	for _, line := range strings.Split(profile, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<") {
			name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "<"), ">")
			if _, closing := strings.CutPrefix(name, "/"); closing {
				block = ""
			} else {
				block = strings.ToLower(name)
			}
			continue
		}
		if block != "" {
			continue
		}
		fields := strings.Fields(stripVPNComment(trimmed))
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "remote":
			if !isVPNRemote(fields) {
				return errors.New("invalid VPN remote directive")
			}
			remoteFound = true
		case "auth-user-pass", "http-proxy-user-pass", "askpass", "script-security", "dns-updown", "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address", "client-crresponse", "plugin", "management", "pkcs12", "cert", "key", "ca", "secret", "tls-auth", "tls-crypt", "tls-crypt-v2":
			return errors.New("VPN profile requires external credentials or execution")
		case "http-proxy":
			if len(fields) > 3 {
				return errors.New("VPN profile requires external credentials or execution")
			}
		case "socks-proxy":
			if len(fields) > 3 || len(fields) == 3 && !isVPNPort(fields[2]) {
				return errors.New("VPN profile requires external credentials or execution")
			}
		}
	}
	if !remoteFound {
		return errors.New("incomplete VPN profile")
	}
	return nil
}

func stripVPNComment(line string) string {
	for index, character := range line {
		if (character == '#' || character == ';') && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			return strings.TrimSpace(line[:index])
		}
	}
	return line
}

func isVPNRemote(fields []string) bool {
	if len(fields) < 2 || len(fields) > 4 || !isVPNHost(fields[1]) {
		return false
	}
	if len(fields) >= 3 && !isVPNPort(fields[2]) {
		return false
	}
	if len(fields) == 4 && !isVPNProtocol(fields[3]) {
		return false
	}
	return true
}

func isVPNHost(host string) bool {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func isVPNProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return true
	default:
		return false
	}
}

func profileTrustChain(blocks map[string]string) (certificateChain, error) {
	trust, ok := blocks["ca"]
	if !ok {
		return certificateChain{}, errors.New("VPN profile has no CA")
	}
	chain, err := parseCertificateChain(trust, time.Now())
	if err != nil {
		return certificateChain{}, fmt.Errorf("invalid VPN profile CA: %w", err)
	}
	return chain, nil
}

func isVPNPort(value string) bool {
	port, err := strconv.ParseUint(value, 10, 16)
	return err == nil && port > 0
}

func (r Runner) unavailableAuth(path string, manifest AuthManifest, reason string) {
	manifest.Reason = reason
	var diagnostic strings.Builder
	diagnostic.WriteString("ict: public auth unavailable: ")
	diagnostic.WriteString(reason)
	diagnostic.WriteByte('\n')
	_, _ = io.WriteString(r.stderr(), diagnostic.String())
	_ = writeAuthManifest(path, manifest)
}

func (r Runner) authOutput(ctx context.Context, environ []string, workspace, name string) (string, error) {
	output, err := r.sensitiveTerraform().SensitiveOutput(ctx, environ, "terraform", "-chdir="+workspace, "output", "-raw", name)
	if err != nil || len(output) == 0 || len(output) > maxAuthOutputBytes {
		return "", errors.New("read auth output")
	}
	return strings.TrimSpace(string(output)), nil
}

// cleanupAuth destroys only the allocation certificate from the companion state.
// Its independent root deliberately has no cluster or VPN data sources.
func (r Runner) cleanupAuth(ctx context.Context, result PlanResult) bool {
	if result.Values.AuthPolicy == nil {
		return true
	}
	authCtx, cancel := context.WithTimeout(ctx, r.authTimeout())
	defer cancel()
	workspace, err := os.MkdirTemp("", "ict-auth-cleanup-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(workspace)
	if err := os.Chmod(workspace, 0o700); err != nil {
		return false
	}
	if err := ictterraform.MaterializeAuthCleanup(workspace); err != nil {
		return false
	}
	if err := ictterraform.MaterializeBackend(workspace); err != nil {
		return false
	}
	tfvars, err := cleanupTFVars(*result.Values.AuthPolicy)
	if err != nil {
		return false
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvars); err != nil {
		return false
	}
	environment := r.authEnvironment(result.Recovery.Endpoints)
	backend := authBackend(result.Backend)
	initArgs := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, backend.InitArgs()...)
	if r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", initArgs...) != nil {
		return false
	}
	return r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", "-chdir="+workspace, "destroy", "-input=false", "-no-color", "-auto-approve", "-refresh=false", "-var-file="+tfvarsPath) == nil
}

func (r Runner) materializeAuth(workspace string) error {
	if r.MaterializeAuth != nil {
		return r.MaterializeAuth(workspace)
	}
	return ictterraform.MaterializeAuth(workspace)
}

func authBackend(backend ictterraform.BackendConfig) ictterraform.BackendConfig {
	backend.Key += ".auth"
	return backend
}

func authTFVars(values Values, configDir string) ([]byte, error) {
	data, err := json.Marshal(struct {
		ClusterName              string `json:"cluster_name"`
		ClusterMode              string `json:"cluster_mode"`
		ResourceGroupName        string `json:"resource_group_name"`
		Region                   string `json:"region"`
		ConfigDir                string `json:"config_dir"`
		AuthAllocationUID        string `json:"auth_allocation_uid"`
		AuthVPNServerID          string `json:"auth_vpn_server_id"`
		AuthSecretsManagerID     string `json:"auth_secrets_manager_id"`
		AuthSecretsManagerRegion string `json:"auth_secrets_manager_region"`
		AuthSecretGroupID        string `json:"auth_secret_group_id"`
		AuthCertificateTemplate  string `json:"auth_certificate_template"`
		AuthIssuer               string `json:"auth_issuer"`
		AuthTTL                  string `json:"auth_ttl"`
	}{values.ClusterName, values.ClusterMode, values.ResourceGroupName, values.Region, configDir, authPolicyValue(values.AuthPolicy).AllocationUID, authPolicyValue(values.AuthPolicy).VPNServerID, authPolicyValue(values.AuthPolicy).SecretsManagerID, authPolicyValue(values.AuthPolicy).SecretsManagerRegion, authPolicyValue(values.AuthPolicy).SecretGroupID, authPolicyValue(values.AuthPolicy).CertificateTemplate, authPolicyValue(values.AuthPolicy).Issuer, authPolicyValue(values.AuthPolicy).TTL})
	if err != nil {
		return nil, err
	}
	return data, nil
}

func authPolicyValue(policy *AuthPolicy) AuthPolicy {
	if policy == nil {
		return AuthPolicy{}
	}
	return *policy
}

func cleanupTFVars(policy AuthPolicy) ([]byte, error) {
	return json.Marshal(struct {
		AuthAllocationUID        string `json:"auth_allocation_uid"`
		AuthSecretsManagerID     string `json:"auth_secrets_manager_id"`
		AuthSecretsManagerRegion string `json:"auth_secrets_manager_region"`
		AuthSecretGroupID        string `json:"auth_secret_group_id"`
		AuthCertificateTemplate  string `json:"auth_certificate_template"`
		AuthTTL                  string `json:"auth_ttl"`
	}{policy.AllocationUID, policy.SecretsManagerID, policy.SecretsManagerRegion, policy.SecretGroupID, policy.CertificateTemplate, policy.TTL})
}

func writeAuthManifest(path string, manifest AuthManifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxAuthManifest {
		return errors.New("auth manifest exceeds byte limit")
	}
	if err := ictterraform.AtomicWrite(path, data); err != nil {
		return err
	}
	return nil
}

func renderKubeconfig(endpoint, ca, certificate, key string) ([]byte, error) {
	if endpoint == "" || ca == "" || certificate == "" || key == "" {
		return nil, errors.New("incomplete public admin material")
	}
	if err := validateKubeconfigMaterial(ca, certificate, key); err != nil {
		return nil, fmt.Errorf("invalid admin certificate material: %w", err)
	}
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	var contents strings.Builder
	contents.WriteString("apiVersion: v1\nkind: Config\nclusters:\n- name: cluster\n  cluster:\n    certificate-authority-data: ")
	contents.WriteString(encode(ca))
	contents.WriteString("\n    server: ")
	contents.WriteString(endpoint)
	contents.WriteString("\ncontexts:\n- name: admin@cluster\n  context:\n    cluster: cluster\n    user: admin\ncurrent-context: admin@cluster\nusers:\n- name: admin\n  user:\n    client-certificate-data: ")
	contents.WriteString(encode(certificate))
	contents.WriteString("\n    client-key-data: ")
	contents.WriteString(encode(key))
	contents.WriteByte('\n')
	return []byte(contents.String()), nil
}

func validateKubeconfig(contents []byte, endpoint string) error {
	text := string(contents)
	lowerText := strings.ToLower(text)
	for _, forbidden := range []string{"exec:", "token:", "auth-provider", "apikey", "api-key", "api_key", "ibm_api_key", "certificate-authority:", "client-certificate:", "client-key:"} {
		if strings.Contains(lowerText, forbidden) {
			return errors.New("kubeconfig contains a non-embedded credential reference")
		}
	}
	if !strings.Contains(text, "server: "+endpoint) && !strings.Contains(text, "server: \""+endpoint+"\"") && !strings.Contains(text, "server: '"+endpoint+"'") {
		return errors.New("kubeconfig does not use the public endpoint")
	}
	ca, err := kubeconfigData(text, "certificate-authority-data:")
	if err != nil {
		return fmt.Errorf("invalid kubeconfig CA: %w", err)
	}
	certificate, err := kubeconfigData(text, "client-certificate-data:")
	if err != nil {
		return fmt.Errorf("invalid kubeconfig client certificate: %w", err)
	}
	key, err := kubeconfigData(text, "client-key-data:")
	if err != nil {
		return fmt.Errorf("invalid kubeconfig client key: %w", err)
	}
	if err := validateKubeconfigMaterial(ca, certificate, key); err != nil {
		return fmt.Errorf("invalid kubeconfig certificate material: %w", err)
	}
	return nil
}

func kubeconfigData(contents, field string) (string, error) {
	for _, line := range strings.Split(contents, "\n") {
		value, found := strings.CutPrefix(strings.TrimSpace(line), field)
		if !found {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return "", errors.New("kubeconfig has invalid embedded certificate material")
		}
		return string(decoded), nil
	}
	return "", errors.New("kubeconfig is not self-contained")
}
