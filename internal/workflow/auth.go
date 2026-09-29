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
	defaultAuthTimeout    = 5 * time.Minute
	maxAuthOutputBytes    = 64 * 1024
	maxAuthManifest       = 4 * 1024
	maxAuthTmpfsBytes     = 512 << 20
	minAuthTmpfsFreeBytes = 384 << 20
	authOutputLockName    = ".ict-auth-export.lock"

	vpnCertificateLeafParseReason         vpnCertificateReason = "vpn-certificate-leaf-parse"
	vpnCertificateLeafUsageReason         vpnCertificateReason = "vpn-certificate-leaf-usage"
	vpnCertificateKeyParseReason          vpnCertificateReason = "vpn-certificate-key-parse"
	vpnCertificateKeyMismatchReason       vpnCertificateReason = "vpn-certificate-key-mismatch"
	vpnCertificateChainParseReason        vpnCertificateReason = "vpn-certificate-chain-parse"
	vpnCertificateChainAuthorityReason    vpnCertificateReason = "vpn-certificate-chain-authority"
	vpnCertificateChainNoRootReason       vpnCertificateReason = "vpn-certificate-chain-no-root"
	vpnCertificateChainVerifyReason       vpnCertificateReason = "vpn-certificate-chain-verify"
	vpnCertificateLeafVerifyReason        vpnCertificateReason = "vpn-certificate-leaf-verify"
	vpnCertificateServerEKUReason         vpnCertificateReason = "vpn-certificate-server-eku"
	vpnCertificateExpiryMismatchReason    vpnCertificateReason = "vpn-certificate-expiry-mismatch"
	vpnCertificateAuthorityMismatchReason vpnCertificateReason = "vpn-certificate-authority-mismatch"
)

// AuthExport identifies private artifact and safe-manifest destinations. Supplying
// neither path disables the optional auth phase.
type AuthExport struct {
	ManifestPath string
	OutputDir    string
}

// AuthManifest is the bounded non-secret handoff for an optional auth export.
type AuthManifest struct {
	Version        int                       `json:"version"`
	Availability   string                    `json:"availability"`
	Reason         string                    `json:"reason,omitempty"`
	CleanupOutcome string                    `json:"cleanup_outcome,omitempty"`
	CleanupReason  string                    `json:"cleanup_reason,omitempty"`
	CleanupStage   cleanupStage              `json:"cleanup_stage,omitempty"`
	Artifacts      []AuthArtifact            `json:"artifacts,omitempty"`
	Mode           string                    `json:"mode,omitempty"`
	Expiry         string                    `json:"expiry,omitempty"`
	Certificate    *AuthCertificateReference `json:"certificate,omitempty"`
}

// AuthArtifact describes a private artifact without serializing its contents.
type AuthArtifact struct {
	Name string `json:"name"`
}

// AuthCertificateReference is the bounded, non-secret identity required to
// verify ownership before deleting an allocation certificate.
type AuthCertificateReference struct {
	ID            string `json:"id,omitempty"`
	AllocationUID string `json:"allocation_uid"`
	AttemptID     string `json:"attempt_id"`
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

// AuthTmpfsVerifier verifies a caller-owned tmpfs mount has the bounded
// capacity contract needed for Terraform state, provider cache, and workspace.
type AuthTmpfsVerifier func(string, int64, int64) (string, error)

var defaultAuthTmpfsVerifier AuthTmpfsVerifier = verifyAuthTmpfs

// authWorkspace creates state only below the caller-provided bounded tmpfs mount.
func (r Runner) authWorkspace(tmpfsDir string) (string, error) {
	root, err := r.validateAuthTmpfs(tmpfsDir)
	if err != nil {
		return "", err
	}
	workspace, err := os.MkdirTemp(root, "ict-auth-")
	if err != nil {
		return "", errors.New("create auth tmpfs workspace")
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = os.RemoveAll(workspace)
		return "", errors.New("protect auth tmpfs workspace")
	}
	return workspace, nil
}

func (r Runner) validateAuthTmpfs(tmpfsDir string) (string, error) {
	if tmpfsDir == "" || !filepath.IsAbs(tmpfsDir) {
		return "", errors.New("auth tmpfs directory must be absolute")
	}
	verifier := r.AuthTmpfsVerifier
	if verifier == nil {
		verifier = defaultAuthTmpfsVerifier
	}
	return verifier(tmpfsDir, maxAuthTmpfsBytes, minAuthTmpfsFreeBytes)
}

func (r Runner) authEnvironment(endpoints config.Endpoints, workspace string) []string {
	environment := r.environment(config.ResolvedTarget{Target: config.Target{Endpoints: endpoints}}.Environment())
	values := make(map[string]string, len(environment)+10)
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	values["TF_LOG"] = "OFF"
	values["TF_LOG_CORE"] = "OFF"
	values["TF_LOG_PROVIDER"] = "OFF"
	if workspace != "" {
		// Auth subprocesses use only the verified tmpfs workspace for scratch
		// and user-scoped state.
		values["HOME"] = filepath.Join(workspace, "home")
		values["TMPDIR"] = filepath.Join(workspace, "tmp")
		values["TF_DATA_DIR"] = filepath.Join(workspace, "tf-data")
		values["TF_PLUGIN_CACHE_DIR"] = filepath.Join(workspace, "plugin-cache")
		values["TF_WORKSPACE"] = "default"
		values["XDG_CACHE_HOME"] = filepath.Join(workspace, "cache")
		values["XDG_CONFIG_HOME"] = filepath.Join(workspace, "config")
		values["XDG_DATA_HOME"] = filepath.Join(workspace, "data")
		values["XDG_STATE_HOME"] = filepath.Join(workspace, "state")
	}
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

var errAuthOutputLocked = errors.New("auth output directory is already in use")

type redactedAuthExportError struct {
	operation string
	err       error
}

func (e redactedAuthExportError) Error() string {
	return "auth export " + e.operation + " failed"
}

func (e redactedAuthExportError) Unwrap() error {
	return e.err
}

func redactAuthExportError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return redactedAuthExportError{operation: operation, err: err}
}

func prepareAuthOutput(outputDir string) (func() error, error) {
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("create auth output directory: %w", err)
	}
	info, err := os.Lstat(outputDir)
	if err != nil {
		return nil, fmt.Errorf("inspect auth output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("auth output directory must be a directory")
	}
	release, err := lockAuthOutput(outputDir)
	if err != nil {
		return nil, err
	}
	if err := removeAuthArtifacts(outputDir); err != nil {
		if releaseErr := release(); releaseErr != nil {
			return nil, errors.Join(err, releaseErr)
		}
		return nil, err
	}
	return release, nil
}

func lockAuthOutput(outputDir string) (func() error, error) {
	path := filepath.Join(outputDir, authOutputLockName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, errAuthOutputLocked
	}
	if err != nil {
		return nil, errors.New("auth output directory lock is unavailable")
	}
	return func() error {
		closeErr := file.Close()
		removeErr := os.Remove(path)
		if closeErr != nil || removeErr != nil {
			return errors.New("release auth output lock")
		}
		return nil
	}, nil
}

func removeAuthArtifacts(outputDir string) error {
	for _, name := range []string{"kubeconfig.yaml", "client.ovpn"} {
		path := filepath.Join(outputDir, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect auth artifact: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("auth artifact must be a regular file")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove auth artifact: %w", err)
		}
	}
	return nil
}

func (r Runner) exportAuth(ctx context.Context, result AuthContext, export AuthExport, tmpfsDir string, attempt AuthAttempt) (resultErr error) {
	if export.ManifestPath == "" {
		return nil
	}
	release, err := prepareAuthOutput(export.OutputDir)
	if err != nil {
		return err
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, redactAuthExportError("output lock release", err))
		}
	}()
	manifest := AuthManifest{Version: 1, Availability: "unavailable", CleanupOutcome: cleanupOutcomeNotRequired}
	if result.Values.ClusterMode == "satellite" {
		manifest.Availability = "unsupported"
		return r.persistAuthManifest(export.ManifestPath, manifest)
	}
	authCtx, cancel := context.WithTimeout(ctx, r.authTimeout())
	defer cancel()
	workspace, err := r.authWorkspace(tmpfsDir)
	if err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "auth-state-failure")
	}
	defer os.RemoveAll(workspace)
	if err := r.materializeAuth(workspace); err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "assets")
	}
	for _, directory := range []string{"credentials", "home", "tmp", "tf-data", "plugin-cache", "cache", "config", "data", "state"} {
		if err := os.Mkdir(filepath.Join(workspace, directory), 0o700); err != nil {
			return r.unavailableAuth(export.ManifestPath, manifest, "auth-state-failure")
		}
	}
	configDir := filepath.Join(workspace, "credentials")
	if err := os.Chmod(configDir, 0o700); err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "credentials-directory")
	}
	tfvars, err := authTFVars(result.Values, attempt, configDir)
	if err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "variables")
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvars); err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "variables-write")
	}
	environment := r.authEnvironment(result.Recovery.Endpoints, workspace)
	if err := r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", "-chdir="+workspace, "init", "-backend=false", "-input=false", "-no-color"); err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "terraform-init")
	}
	if err := r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", "-chdir="+workspace, "apply", "-state="+filepath.Join(workspace, "terraform.tfstate"), "-backup=-", "-input=false", "-no-color", "-auto-approve", "-var-file="+tfvarsPath); err != nil {
		return r.unavailableAfterVPNFailure(authCtx, export.ManifestPath, manifest, "terraform-apply", result.Values.AuthPolicy, &attempt, result.Recovery.Endpoints, nil)
	}
	mode, err := r.authOutput(authCtx, environment, workspace, "auth_mode")
	if err != nil {
		return r.unavailableAfterVPNFailure(authCtx, export.ManifestPath, manifest, "auth-mode", result.Values.AuthPolicy, &attempt, result.Recovery.Endpoints, nil)
	}
	switch mode {
	case "public":
		manifest.Mode = "public"
	case "vpn":
		if result.Values.AuthPolicy == nil {
			return r.unavailableAfterVPNFailure(authCtx, export.ManifestPath, manifest, "private-policy", nil, &attempt, result.Recovery.Endpoints, nil)
		}
		return r.exportVPNAuth(authCtx, environment, workspace, export, manifest, *result.Values.AuthPolicy, attempt, result.Recovery.Endpoints)
	case "unsupported":
		manifest.Availability = "unsupported"
		return r.persistAuthManifest(export.ManifestPath, manifest)
	default:
		return r.unavailableAfterVPNFailure(authCtx, export.ManifestPath, manifest, "auth-mode", result.Values.AuthPolicy, &attempt, result.Recovery.Endpoints, nil)
	}
	endpoint, err := r.authOutput(authCtx, environment, workspace, "public_endpoint")
	if err != nil || endpoint == "" {
		return r.unavailableAuth(export.ManifestPath, manifest, "public-endpoint")
	}
	ca, err := r.authOutput(authCtx, environment, workspace, "public_ca_certificate")
	if err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "admin-material")
	}
	certificate, err := r.authOutput(authCtx, environment, workspace, "public_admin_certificate")
	if err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "admin-material")
	}
	key, err := r.authOutput(authCtx, environment, workspace, "public_admin_key")
	if err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "admin-material")
	}
	contents, err := renderKubeconfig(endpoint, ca, certificate, key)
	if err != nil || validateKubeconfig(contents, endpoint) != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "kubeconfig-render")
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "kubeconfig.yaml"), contents); err != nil {
		return r.unavailableAuth(export.ManifestPath, manifest, "kubeconfig-write")
	}
	manifest.Availability = "available"
	manifest.Artifacts = []AuthArtifact{{Name: "kubeconfig.yaml"}}
	if err := r.persistAuthManifest(export.ManifestPath, manifest); err != nil {
		return r.compensateAvailablePublicManifestFailure(export, err)
	}
	return nil
}

func (r Runner) compensateAvailablePublicManifestFailure(export AuthExport, availableErr error) error {
	removalErr := removeAuthArtifacts(export.OutputDir)
	unavailableErr := r.unavailableAuth(export.ManifestPath, AuthManifest{Version: 1, Availability: "unavailable", CleanupOutcome: cleanupOutcomeNotRequired}, "manifest-write")
	return errors.Join(
		redactAuthExportError("available manifest", availableErr),
		redactAuthExportError("artifact removal", removalErr),
		redactAuthExportError("unavailable manifest", unavailableErr),
	)
}

func (r Runner) exportVPNAuth(ctx context.Context, environ []string, workspace string, export AuthExport, manifest AuthManifest, policy AuthPolicy, attempt AuthAttempt, endpoints config.Endpoints) error {
	fail := func(reason string, reference *AuthCertificateReference) error {
		return r.unavailableAfterVPNFailure(ctx, export.ManifestPath, manifest, reason, &policy, &attempt, endpoints, reference)
	}
	endpoint, err := r.authOutput(ctx, environ, workspace, "private_endpoint")
	if err != nil || endpoint == "" {
		return fail("private-endpoint", nil)
	}
	outputs := make(map[string]string, 10)
	for _, name := range []string{"vpn_certificate_id", "private_ca_certificate", "private_admin_certificate", "private_admin_key", "vpn_profile", "vpn_certificate", "vpn_private_key", "vpn_ca_chain", "vpn_expiry", "vpn_certificate_authority"} {
		outputs[name], err = r.authOutput(ctx, environ, workspace, name)
		if err != nil {
			return fail("private-material", nil)
		}
	}
	if outputs["vpn_certificate_id"] == "" {
		return fail("invalid-artifacts", nil)
	}
	reference := &AuthCertificateReference{ID: outputs["vpn_certificate_id"], AllocationUID: attempt.AllocationUID, AttemptID: attempt.AttemptID}
	manifest.Certificate = reference
	kubeconfig, err := renderKubeconfig(endpoint, outputs["private_ca_certificate"], outputs["private_admin_certificate"], outputs["private_admin_key"])
	if err != nil || validateKubeconfig(kubeconfig, endpoint) != nil {
		return fail("kubeconfig-render", reference)
	}
	expiry, err := validateVPNCertificate(outputs["vpn_certificate"], outputs["vpn_private_key"], outputs["vpn_ca_chain"], outputs["vpn_expiry"])
	if err != nil {
		return fail(vpnCertificateFailureReason(err), reference)
	}
	if outputs["vpn_certificate_authority"] != policy.Issuer {
		return fail(string(vpnCertificateAuthorityMismatchReason), reference)
	}
	profile, err := renderVPNProfile(outputs["vpn_profile"], outputs["vpn_certificate"], outputs["vpn_private_key"], outputs["vpn_ca_chain"])
	if err != nil {
		return fail("vpn-profile", reference)
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "kubeconfig.yaml"), kubeconfig); err != nil {
		return fail("kubeconfig-write", reference)
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "client.ovpn"), profile); err != nil {
		_ = removeAuthArtifacts(export.OutputDir)
		return fail("vpn-write", reference)
	}
	manifest.Availability = "available"
	manifest.Mode = "vpn"
	manifest.Expiry = expiry.Format(time.RFC3339)
	manifest.Artifacts = []AuthArtifact{{Name: "kubeconfig.yaml"}, {Name: "client.ovpn"}}
	if err := r.persistAuthManifest(export.ManifestPath, manifest); err != nil {
		return r.compensateAvailableVPNManifestFailure(ctx, export, policy, attempt, endpoints, reference, err)
	}
	return nil
}

func (r Runner) compensateAvailableVPNManifestFailure(ctx context.Context, export AuthExport, policy AuthPolicy, attempt AuthAttempt, endpoints config.Endpoints, reference *AuthCertificateReference, availableErr error) error {
	removalErr := removeAuthArtifacts(export.OutputDir)
	outcome, unavailableErr := r.unavailableAfterVPNFailureOutcome(ctx, export.ManifestPath, AuthManifest{Version: 1, Availability: "unavailable", CleanupOutcome: cleanupOutcomeNotRequired}, "manifest-write", &policy, &attempt, endpoints, reference)
	var cleanupErr error
	if outcome.Status == cleanupOutcomePending {
		cleanupErr = errors.New("certificate cleanup is pending")
	}
	return errors.Join(
		redactAuthExportError("available manifest", availableErr),
		redactAuthExportError("artifact removal", removalErr),
		redactAuthExportError("certificate cleanup", cleanupErr),
		redactAuthExportError("unavailable manifest", unavailableErr),
	)
}

func (r Runner) unavailableAfterVPNFailure(ctx context.Context, manifestPath string, manifest AuthManifest, reason string, policy *AuthPolicy, attempt *AuthAttempt, endpoints config.Endpoints, reference *AuthCertificateReference) error {
	_, err := r.unavailableAfterVPNFailureOutcome(ctx, manifestPath, manifest, reason, policy, attempt, endpoints, reference)
	return err
}

func (r Runner) unavailableAfterVPNFailureOutcome(ctx context.Context, manifestPath string, manifest AuthManifest, reason string, policy *AuthPolicy, attempt *AuthAttempt, endpoints config.Endpoints, reference *AuthCertificateReference) (certificateCleanupOutcome, error) {
	outcome := certificateCleanupOutcome{Status: cleanupOutcomeNotRequired}
	if policy != nil {
		references := []AuthCertificateReference{}
		if reference != nil {
			references = append(references, *reference)
		}
		outcome = r.cleanupCertificates(ctx, *policy, endpoints, attempt.AllocationUID, attempt, references...)
		manifest.Certificate = nil
		manifest.CleanupOutcome = outcome.Status
		manifest.CleanupReason = outcome.Reason
		manifest.CleanupStage = outcome.Stage
		if outcome.Status == cleanupOutcomePending {
			manifest.Certificate = outcome.Certificate
		}
	}
	return outcome, r.unavailableAuth(manifestPath, manifest, reason)
}

type certificateChain struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

type vpnCertificateReason string

func (reason vpnCertificateReason) Error() string {
	return string(reason)
}

func vpnCertificateFailureReason(err error) string {
	var reason vpnCertificateReason
	if errors.As(err, &reason) {
		return string(reason)
	}
	return string(vpnCertificateLeafVerifyReason)
}

func validateVPNCertificate(certificatePEM, keyPEM, chainPEM, reportedExpiry string) (time.Time, error) {
	certificate, err := validateVPNCertificateAndKey(certificatePEM, keyPEM, chainPEM)
	if err != nil {
		return time.Time{}, err
	}
	if containsUsage(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return time.Time{}, vpnCertificateServerEKUReason
	}
	reported, err := time.Parse(time.RFC3339, reportedExpiry)
	if err != nil || !reported.Equal(certificate.NotAfter.UTC()) {
		return time.Time{}, vpnCertificateExpiryMismatchReason
	}
	return certificate.NotAfter.UTC(), nil
}

// validateVPNCertificateAndKey verifies the client presentation chain separately
// from trust bundles. Its final supplied CA is the explicit trust anchor.
func validateVPNCertificateAndKey(certificatePEM, keyPEM, chainPEM string) (*x509.Certificate, error) {
	certificates, err := parseCertificates(certificatePEM)
	if err != nil || len(certificates) != 1 {
		return nil, vpnCertificateLeafParseReason
	}
	certificate := certificates[0]
	now := time.Now()
	if !certificateValidAt(certificate, now) || certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !containsUsage(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return nil, vpnCertificateLeafUsageReason
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, vpnCertificateKeyParseReason
	}
	if !publicKeysEqual(key.Public(), certificate.PublicKey) {
		return nil, vpnCertificateKeyMismatchReason
	}
	chain, err := parseVPNPresentationChain(chainPEM, certificate, now)
	if err != nil {
		return nil, err
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: chain.roots, Intermediates: chain.intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, vpnCertificateLeafVerifyReason
	}
	return certificate, nil
}

func parseVPNPresentationChain(value string, leaf *x509.Certificate, now time.Time) (certificateChain, error) {
	certificates, err := parseCertificates(value)
	if err != nil || len(certificates) == 0 {
		return certificateChain{}, vpnCertificateChainParseReason
	}
	for _, certificate := range certificates {
		if !certificateValidAt(certificate, now) || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return certificateChain{}, vpnCertificateChainAuthorityReason
		}
	}
	if leaf.CheckSignatureFrom(certificates[0]) != nil {
		return certificateChain{}, vpnCertificateChainVerifyReason
	}
	for index := 0; index+1 < len(certificates); index++ {
		if certificates[index].CheckSignatureFrom(certificates[index+1]) != nil {
			return certificateChain{}, vpnCertificateChainVerifyReason
		}
	}
	chain := certificateChain{roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	for index, certificate := range certificates {
		if index == len(certificates)-1 {
			chain.roots.AddCert(certificate)
		} else {
			chain.intermediates.AddCert(certificate)
		}
	}
	return chain, nil
}

func validateKubeconfigMaterial(caPEM, certificatePEM, keyPEM string) error {
	_, err := validateCertificateAndKey(certificatePEM, keyPEM, caPEM, x509.ExtKeyUsageClientAuth)
	return err
}

func validateCertificateAndKey(certificatePEM, keyPEM, chainPEM string, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	certificates, err := parseCertificates(certificatePEM)
	if err != nil || len(certificates) != 1 {
		return nil, vpnCertificateLeafParseReason
	}
	certificate := certificates[0]
	now := time.Now()
	if !certificateValidAt(certificate, now) || certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !containsUsage(certificate.ExtKeyUsage, usage) {
		return nil, vpnCertificateLeafUsageReason
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, vpnCertificateKeyParseReason
	}
	if !publicKeysEqual(key.Public(), certificate.PublicKey) {
		return nil, vpnCertificateKeyMismatchReason
	}
	chain, err := parseCertificateChain(chainPEM, now)
	if err != nil {
		return nil, err
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: chain.roots, Intermediates: chain.intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, vpnCertificateLeafVerifyReason
	}
	return certificate, nil
}

func parseCertificateChain(value string, now time.Time) (certificateChain, error) {
	certificates, err := parseCertificates(value)
	if err != nil || len(certificates) == 0 {
		return certificateChain{}, vpnCertificateChainParseReason
	}
	chain := certificateChain{roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	roots := 0
	for _, certificate := range certificates {
		if !certificateValidAt(certificate, now) || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return certificateChain{}, vpnCertificateChainAuthorityReason
		}
		if certificate.CheckSignatureFrom(certificate) == nil {
			chain.roots.AddCert(certificate)
			roots++
		} else {
			chain.intermediates.AddCert(certificate)
		}
	}
	if roots == 0 {
		return certificateChain{}, vpnCertificateChainNoRootReason
	}
	for _, certificate := range certificates {
		if certificate.CheckSignatureFrom(certificate) == nil {
			continue
		}
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: chain.roots, Intermediates: chain.intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return certificateChain{}, vpnCertificateChainVerifyReason
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

func (r Runner) unavailableAuth(path string, manifest AuthManifest, reason string) error {
	manifest.Reason = reason
	if manifest.CleanupOutcome == "" {
		manifest.CleanupOutcome = cleanupOutcomeNotRequired
	}
	var diagnostic strings.Builder
	diagnostic.WriteString("ict: public auth unavailable: ")
	diagnostic.WriteString(reason)
	diagnostic.WriteByte('\n')
	_, _ = io.WriteString(r.stderr(), diagnostic.String())
	return r.persistAuthManifest(path, manifest)
}

func (r Runner) persistAuthManifest(path string, manifest AuthManifest) error {
	if r.AuthManifestWriter != nil {
		if err := r.AuthManifestWriter(path, manifest); err != nil {
			return fmt.Errorf("persist auth manifest: %w", err)
		}
		return nil
	}
	if err := writeAuthManifest(path, manifest); err != nil {
		return fmt.Errorf("persist auth manifest: %w", err)
	}
	return nil
}

func (r Runner) authOutput(ctx context.Context, environ []string, workspace, name string) (string, error) {
	output, err := r.sensitiveTerraform().SensitiveOutput(ctx, environ, "terraform", "-chdir="+workspace, "output", "-raw", name)
	if err != nil || len(output) == 0 || len(output) > maxAuthOutputBytes {
		return "", errors.New("read auth output")
	}
	return strings.TrimSpace(string(output)), nil
}

func (r Runner) materializeAuth(workspace string) error {
	if r.MaterializeAuth != nil {
		return r.MaterializeAuth(workspace)
	}
	return ictterraform.MaterializeAuth(workspace)
}

func authTFVars(values Values, attempt AuthAttempt, configDir string) ([]byte, error) {
	data, err := json.Marshal(struct {
		ClusterName              string `json:"cluster_name"`
		ClusterMode              string `json:"cluster_mode"`
		ResourceGroupName        string `json:"resource_group_name"`
		Region                   string `json:"region"`
		ConfigDir                string `json:"config_dir"`
		AuthAllocationUID        string `json:"auth_allocation_uid"`
		AuthAttemptID            string `json:"auth_attempt_id"`
		AuthVPNServerID          string `json:"auth_vpn_server_id"`
		AuthSecretsManagerID     string `json:"auth_secrets_manager_id"`
		AuthSecretsManagerRegion string `json:"auth_secrets_manager_region"`
		AuthSecretGroupID        string `json:"auth_secret_group_id"`
		AuthCertificateTemplate  string `json:"auth_certificate_template"`
		AuthIssuer               string `json:"auth_issuer"`
		AuthTTL                  string `json:"auth_ttl"`
	}{values.ClusterName, values.ClusterMode, values.ResourceGroupName, values.Region, configDir, attempt.AllocationUID, attempt.AttemptID, authPolicyValue(values.AuthPolicy).VPNServerID, authPolicyValue(values.AuthPolicy).SecretsManagerID, authPolicyValue(values.AuthPolicy).SecretsManagerRegion, authPolicyValue(values.AuthPolicy).SecretGroupID, authPolicyValue(values.AuthPolicy).CertificateTemplate, authPolicyValue(values.AuthPolicy).Issuer, authPolicyValue(values.AuthPolicy).TTL})
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
