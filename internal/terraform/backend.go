package terraform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const backendVersion = 1

var (
	backendBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	backendRegionPattern = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+$`)
)

// BackendConfig is the non-secret S3 backend configuration for IBM COS.
type BackendConfig struct {
	Version                   int    `json:"version"`
	Bucket                    string `json:"bucket"`
	Key                       string `json:"key"`
	Region                    string `json:"region"`
	Endpoint                  string `json:"endpoint"`
	SkipCredentialsValidation bool   `json:"skip_credentials_validation"`
	SkipMetadataAPICheck      bool   `json:"skip_metadata_api_check"`
	SkipRegionValidation      bool   `json:"skip_region_validation"`
	SkipRequestingAccountID   bool   `json:"skip_requesting_account_id"`
	ForcePathStyle            bool   `json:"force_path_style,omitempty"`
	UseLockfile               bool   `json:"use_lockfile,omitempty"`
}

// LoadBackendConfig strictly reads one complete non-secret backend configuration.
func LoadBackendConfig(path string) (BackendConfig, error) {
	if err := validateExternalPath(path, "backend configuration"); err != nil {
		return BackendConfig{}, fmt.Errorf("validate backend configuration path: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return BackendConfig{}, fmt.Errorf("read backend configuration %q: %w", path, err)
	}
	config, err := DecodeBackendConfig(data)
	if err != nil {
		return BackendConfig{}, fmt.Errorf("decode backend configuration %q: %w", path, err)
	}
	return config, nil
}

// DecodeBackendConfig strictly decodes and validates one complete backend configuration.
func DecodeBackendConfig(data []byte) (BackendConfig, error) {
	type wire struct {
		Version                   *int    `json:"version"`
		Bucket                    *string `json:"bucket"`
		Key                       *string `json:"key"`
		Region                    *string `json:"region"`
		Endpoint                  *string `json:"endpoint"`
		SkipCredentialsValidation *bool   `json:"skip_credentials_validation"`
		SkipMetadataAPICheck      *bool   `json:"skip_metadata_api_check"`
		SkipRegionValidation      *bool   `json:"skip_region_validation"`
		SkipRequestingAccountID   *bool   `json:"skip_requesting_account_id"`
		ForcePathStyle            *bool   `json:"force_path_style"`
		UseLockfile               *bool   `json:"use_lockfile"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded wire
	if err := decoder.Decode(&decoded); err != nil {
		return BackendConfig{}, fmt.Errorf("decode backend configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BackendConfig{}, errors.New("backend configuration contains trailing JSON")
	}
	if decoded.Version == nil || decoded.Bucket == nil || decoded.Key == nil || decoded.Region == nil || decoded.Endpoint == nil || decoded.SkipCredentialsValidation == nil || decoded.SkipMetadataAPICheck == nil || decoded.SkipRegionValidation == nil || decoded.SkipRequestingAccountID == nil {
		return BackendConfig{}, errors.New("backend configuration is incomplete")
	}
	config := BackendConfig{
		Version:                   *decoded.Version,
		Bucket:                    *decoded.Bucket,
		Key:                       *decoded.Key,
		Region:                    *decoded.Region,
		Endpoint:                  *decoded.Endpoint,
		SkipCredentialsValidation: *decoded.SkipCredentialsValidation,
		SkipMetadataAPICheck:      *decoded.SkipMetadataAPICheck,
		SkipRegionValidation:      *decoded.SkipRegionValidation,
		SkipRequestingAccountID:   *decoded.SkipRequestingAccountID,
	}
	if decoded.ForcePathStyle != nil {
		config.ForcePathStyle = *decoded.ForcePathStyle
	}
	if decoded.UseLockfile != nil {
		config.UseLockfile = *decoded.UseLockfile
	}
	if err := config.Validate(); err != nil {
		return BackendConfig{}, err
	}
	return config, nil
}

// Validate verifies that backend configuration is safe to serialize and pass to Terraform.
func (c BackendConfig) Validate() error {
	if c.Version != backendVersion {
		return fmt.Errorf("unsupported backend configuration version %d", c.Version)
	}
	if !backendBucketPattern.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") {
		return fmt.Errorf("invalid backend bucket %q", c.Bucket)
	}
	if err := validateBackendKey(c.Key); err != nil {
		return fmt.Errorf("validate backend key: %w", err)
	}
	if !backendRegionPattern.MatchString(c.Region) {
		return fmt.Errorf("invalid backend region %q", c.Region)
	}
	if c.UseLockfile {
		return errors.New("backend use_lockfile requires Terraform 1.10, but ICT supports Terraform 1.5+")
	}
	endpoint, err := url.ParseRequestURI(c.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("backend endpoint must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

// InitArgs returns deterministic non-secret Terraform init backend arguments.
func (c BackendConfig) InitArgs() []string {
	// Terraform 1.5 rejects skip_requesting_account_id for the S3 backend.
	return []string{
		"-backend-config=bucket=" + c.Bucket,
		"-backend-config=key=" + c.Key,
		"-backend-config=region=" + c.Region,
		"-backend-config=endpoint=" + c.Endpoint,
		fmt.Sprintf("-backend-config=skip_credentials_validation=%t", c.SkipCredentialsValidation),
		fmt.Sprintf("-backend-config=skip_metadata_api_check=%t", c.SkipMetadataAPICheck),
		fmt.Sprintf("-backend-config=skip_region_validation=%t", c.SkipRegionValidation),
		fmt.Sprintf("-backend-config=force_path_style=%t", c.ForcePathStyle),
	}
}

// MaterializeBackend writes the S3 backend declaration used with InitArgs.
func MaterializeBackend(workspace string) error {
	if err := atomicWrite(filepath.Join(workspace, "backend.tf"), []byte("terraform {\n  backend \"s3\" {}\n}\n")); err != nil {
		return fmt.Errorf("write Terraform backend declaration: %w", err)
	}
	return nil
}

// ValidateResultPath rejects ambiguous or traversal-containing result paths.
func ValidateResultPath(path string) error {
	if err := validateExternalPath(path, "result file"); err != nil {
		return fmt.Errorf("validate result file path: %w", err)
	}
	return nil
}

func validateBackendKey(key string) error {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return fmt.Errorf("invalid backend key %q", key)
	}
	parts := strings.Split(key, "/")
	if slices.Contains(parts, "") || slices.Contains(parts, ".") || slices.Contains(parts, "..") {
		return fmt.Errorf("invalid backend key %q", key)
	}
	return nil
}

func validateExternalPath(path, name string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute", name)
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return fmt.Errorf("%s path must not contain parent traversal", name)
		}
	}
	return nil
}
