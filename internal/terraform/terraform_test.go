package terraform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateStateID(t *testing.T) {
	for _, stateID := range []string{"a", "Slack_User.1", strings.Repeat("a", 128)} {
		if err := ValidateStateID(stateID); err != nil {
			t.Fatalf("ValidateStateID(%q) = %v", stateID, err)
		}
	}
	for _, stateID := range []string{"", ".hidden", ".", "..", "a/b", `a\\b`, "a/../b", "naive-é", strings.Repeat("a", 129)} {
		if err := ValidateStateID(stateID); err == nil {
			t.Fatalf("ValidateStateID(%q) succeeded", stateID)
		}
	}
}

func TestMaterializeOmitsRepositoryTestFiles(t *testing.T) {
	workspace := t.TempDir()
	if err := Materialize(workspace); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"main.tf", "variables.tf", ".terraform.lock.hcl"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); err != nil {
			t.Fatalf("missing production file %s: %v", name, err)
		}
	}
	for _, name := range []string{"cluster-name.tftest.hcl", "satellite-topology.tftest.hcl", "vpc-reuse.tftest.hcl"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); !os.IsNotExist(err) {
			t.Fatalf("materialized test file %s: %v", name, err)
		}
	}
}

func TestMaterializeAuthUsesPinnedIsolatedRoot(t *testing.T) {
	workspace := t.TempDir()
	if err := MaterializeAuth(workspace); err != nil {
		t.Fatal(err)
	}
	main := string(mustReadAuth(t, filepath.Join(workspace, "main.tf")))
	if !strings.Contains(main, "ibm_container_cluster_config") || !strings.Contains(main, "public_service_endpoint") {
		t.Fatalf("public auth root does not classify and export public config: %s", main)
	}
	if strings.Contains(main, "endpoint_type") {
		t.Fatalf("public auth root must use the provider's default public endpoint: %s", main)
	}
	lock := string(mustReadAuth(t, filepath.Join(workspace, ".terraform.lock.hcl")))
	if !strings.Contains(lock, "version     = \"2.5.0\"") {
		t.Fatalf("auth root does not pin provider: %s", lock)
	}
}

func mustReadAuth(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAtomicWriteIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "runtime.json")
	if err := AtomicWrite(path, []byte("value")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime file = %v, %v", info, err)
	}
}
