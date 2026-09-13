package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
	Artifacts    []AuthArtifact `json:"artifacts,omitempty"`
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

func (r Runner) exportPublicAuth(ctx context.Context, result PlanResult, export AuthExport) {
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
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	authCtx, cancel := context.WithTimeout(ctx, r.authTimeout())
	defer cancel()
	workspace, err := os.MkdirTemp("", "ict-auth-")
	if err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	defer os.RemoveAll(workspace)
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	if err := r.materializeAuth(workspace); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	configDir := filepath.Join(workspace, "credentials")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	tfvars, err := authTFVars(result.Values, configDir)
	if err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvars); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	if err := ictterraform.MaterializeBackend(workspace); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	backend := authBackend(result.Backend)
	environment := r.authEnvironment(result.Recovery.Endpoints)
	initArgs := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, backend.InitArgs()...)
	if err := r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", initArgs...); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	if err := r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", "-chdir="+workspace, "apply", "-input=false", "-no-color", "-auto-approve", "-var-file="+tfvarsPath); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	available, err := r.authOutput(authCtx, environment, workspace, "public_available")
	if err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	switch available {
	case "true":
	case "false":
		manifest.Availability = "unsupported"
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	default:
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	endpoint, err := r.authOutput(authCtx, environment, workspace, "public_endpoint")
	if err != nil || endpoint == "" {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	configPath, err := r.authOutput(authCtx, environment, workspace, "kubeconfig_path")
	if err != nil || configPath == "" || !filepath.IsAbs(configPath) {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	relativeConfigPath, err := filepath.Rel(configDir, configPath)
	if err != nil || relativeConfigPath == ".." || strings.HasPrefix(relativeConfigPath, ".."+string(filepath.Separator)) {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	contents, err := os.ReadFile(configPath)
	if err != nil || validateKubeconfig(contents, endpoint) != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	if err := ictterraform.AtomicWrite(filepath.Join(export.OutputDir, "kubeconfig.yaml"), contents); err != nil {
		_ = writeAuthManifest(export.ManifestPath, manifest)
		return
	}
	manifest.Availability = "available"
	manifest.Artifacts = []AuthArtifact{{Name: "kubeconfig.yaml"}}
	_ = writeAuthManifest(export.ManifestPath, manifest)
}

func (r Runner) authOutput(ctx context.Context, environ []string, workspace, name string) (string, error) {
	output, err := r.sensitiveTerraform().SensitiveOutput(ctx, environ, "terraform", "-chdir="+workspace, "output", "-raw", name)
	if err != nil || len(output) == 0 || len(output) > maxAuthOutputBytes {
		return "", errors.New("read auth output")
	}
	return strings.TrimSpace(string(output)), nil
}

func (r Runner) cleanupAuth(ctx context.Context, result PlanResult) {
	authCtx, cancel := context.WithTimeout(ctx, r.authTimeout())
	defer cancel()
	workspace, err := os.MkdirTemp("", "ict-auth-cleanup-")
	if err != nil {
		return
	}
	defer os.RemoveAll(workspace)
	if err := os.Chmod(workspace, 0o700); err != nil {
		return
	}
	if err := r.materializeAuth(workspace); err != nil {
		return
	}
	if err := ictterraform.MaterializeBackend(workspace); err != nil {
		return
	}
	tfvars, err := authTFVars(result.Values, filepath.Join(workspace, "credentials"))
	if err != nil {
		return
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvars); err != nil {
		return
	}
	environment := r.authEnvironment(result.Recovery.Endpoints)
	backend := authBackend(result.Backend)
	initArgs := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, backend.InitArgs()...)
	if r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", initArgs...) != nil {
		return
	}
	_ = r.terraform().Run(authCtx, environment, io.Discard, io.Discard, "terraform", "-chdir="+workspace, "destroy", "-input=false", "-no-color", "-auto-approve", "-refresh=false", "-var-file="+tfvarsPath)
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
		ClusterName       string `json:"cluster_name"`
		ResourceGroupName string `json:"resource_group_name"`
		Region            string `json:"region"`
		ConfigDir         string `json:"config_dir"`
	}{values.ClusterName, values.ResourceGroupName, values.Region, configDir})
	if err != nil {
		return nil, err
	}
	return data, nil
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

func validateKubeconfig(contents []byte, endpoint string) error {
	text := string(contents)
	lowerText := strings.ToLower(text)
	for _, forbidden := range []string{"exec:", "token:", "auth-provider", "apikey", "api-key", "api_key", "ibm_api_key", "certificate-authority:", "client-certificate:", "client-key:"} {
		if strings.Contains(lowerText, forbidden) {
			return errors.New("kubeconfig contains a non-embedded credential reference")
		}
	}
	for _, required := range []string{"certificate-authority-data:", "client-certificate-data:", "client-key-data:"} {
		if !strings.Contains(text, required) {
			return errors.New("kubeconfig is not self-contained")
		}
	}
	if !strings.Contains(text, "server: "+endpoint) && !strings.Contains(text, "server: \""+endpoint+"\"") && !strings.Contains(text, "server: '"+endpoint+"'") {
		return errors.New("kubeconfig does not use the public endpoint")
	}
	return nil
}
