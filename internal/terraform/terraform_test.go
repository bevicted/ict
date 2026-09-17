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
	if !strings.Contains(main, "ibm_container_cluster_config") || !strings.Contains(main, "ibm_container_vpc_cluster") || !strings.Contains(main, "ibm_container_cluster") || !strings.Contains(main, "public_service_endpoint") {
		t.Fatalf("public auth root does not select the cluster provider and export public config: %s", main)
	}
	if !strings.Contains(main, `endpoint_type     = "private"`) || !strings.Contains(main, "ibm_sm_private_certificate") || !strings.Contains(main, "ibm_is_vpn_server_client_configuration") {
		t.Fatalf("auth root does not materialize the private VPN bundle: %s", main)
	}
	lock := string(mustReadAuth(t, filepath.Join(workspace, ".terraform.lock.hcl")))
	if !strings.Contains(lock, "version     = \"2.5.0\"") {
		t.Fatalf("auth root does not pin provider: %s", lock)
	}
}

func TestMaterializeAuthRequiresPrivateEndpointURLForVPN(t *testing.T) {
	workspace := t.TempDir()
	if err := MaterializeAuth(workspace); err != nil {
		t.Fatal(err)
	}
	main := string(mustReadAuth(t, filepath.Join(workspace, "main.tf")))
	if !strings.Contains(main, `data.ibm_container_vpc_cluster.target[0].private_service_endpoint && trimspace(data.ibm_container_vpc_cluster.target[0].private_service_endpoint_url) != ""`) {
		t.Fatalf("private VPN eligibility does not require a usable endpoint URL: %s", main)
	}
}

func TestMaterializeAuthCleanupUsesPinnedClusterIndependentRoot(t *testing.T) {
	workspace := t.TempDir()
	if err := MaterializeAuthCleanup(workspace); err != nil {
		t.Fatal(err)
	}
	main := string(mustReadAuth(t, filepath.Join(workspace, "main.tf")))
	if !strings.Contains(main, `resource "ibm_sm_private_certificate" "allocation"`) || strings.Contains(main, `data "ibm_container`) || strings.Contains(main, "vpn_server_client_configuration") {
		t.Fatalf("cleanup root is not certificate-only: %s", main)
	}
	lock := string(mustReadAuth(t, filepath.Join(workspace, ".terraform.lock.hcl")))
	if !strings.Contains(lock, "version     = \"2.5.0\"") {
		t.Fatalf("cleanup root does not pin IBM provider 2.5.0: %s", lock)
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
