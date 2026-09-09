package terraform

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const validBackendConfig = `{
  "version": 1,
  "bucket": "ict-state-bucket",
  "key": "allocations/cluster-123.tfstate",
  "region": "us-south",
  "endpoint": "https://s3.us-south.cloud-object-storage.appdomain.cloud",
  "skip_credentials_validation": true,
  "skip_metadata_api_check": true,
  "skip_region_validation": true,
  "skip_requesting_account_id": true,
  "force_path_style": true
}`

func TestDecodeBackendConfigStrictlyValidatesNonSecretCOSSettings(t *testing.T) {
	backend, err := DecodeBackendConfig([]byte(validBackendConfig))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := backend.InitArgs(), []string{
		"-backend-config=bucket=ict-state-bucket",
		"-backend-config=key=allocations/cluster-123.tfstate",
		"-backend-config=region=us-south",
		"-backend-config=endpoint=https://s3.us-south.cloud-object-storage.appdomain.cloud",
		"-backend-config=skip_credentials_validation=true",
		"-backend-config=skip_metadata_api_check=true",
		"-backend-config=skip_region_validation=true",
		"-backend-config=force_path_style=true",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("init arguments = %#v, want %#v", got, want)
	}

	for _, test := range []struct {
		name string
		data string
	}{
		{"missing required field", strings.Replace(validBackendConfig, "\n  \"region\": \"us-south\",", "", 1)},
		{"unknown credential field", strings.Replace(validBackendConfig, "\n}", ",\n  \"access_key\": \"not-allowed\"\n}", 1)},
		{"trailing JSON", validBackendConfig + "\n{}"},
		{"unsafe key", strings.Replace(validBackendConfig, "allocations/cluster-123.tfstate", "../cluster.tfstate", 1)},
		{"credential endpoint", strings.Replace(validBackendConfig, "https://s3.us-south.cloud-object-storage.appdomain.cloud", "https://user:secret@example.invalid", 1)},
		{"unsupported lockfile", strings.Replace(validBackendConfig, "\n}", ",\n  \"use_lockfile\": true\n}", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeBackendConfig([]byte(test.data)); err == nil {
				t.Fatal("invalid backend configuration was accepted")
			}
		})
	}
}

func TestBackendExternalPathsAndMaterialization(t *testing.T) {
	if _, err := LoadBackendConfig("relative.json"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative backend configuration error = %v", err)
	}
	if err := ValidateResultPath("../result.json"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("unsafe result path error = %v", err)
	}

	workspace := t.TempDir()
	if err := MaterializeBackend(workspace); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "backend.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "terraform {\n  backend \"s3\" {}\n}\n"; got != want {
		t.Fatalf("backend declaration = %q, want %q", got, want)
	}
}
