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
