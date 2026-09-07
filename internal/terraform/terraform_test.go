package terraform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceUsesStateRootAndStateID(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	for _, stateID := range []string{DefaultStateID, "Slack_User.1", "a", strings.Repeat("a", 128)} {
		t.Run(stateID, func(t *testing.T) {
			workspace, err := Workspace(stateID)
			if err != nil {
				t.Fatal(err)
			}
			root, err := StateRoot()
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(root, stateID)
			if workspace != want {
				t.Fatalf("workspace = %q, want %q", workspace, want)
			}
			if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
				t.Fatalf("Workspace created the state root: %v", err)
			}
		})
	}
}

func TestReserveWorkspaceIsAtomicAndPrivate(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "state", "ict", "one")
	if err := ReserveWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(workspace)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("workspace = %v, %v", info, err)
	}
	if err := ReserveWorkspace(workspace); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second reservation error = %v", err)
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
		if _, err := os.Stat(filepath.Join("assets", name)); err != nil {
			t.Fatalf("repository test source %s missing: %v", name, err)
		}
	}
}

func TestWorkspaceFallsBackToLocalState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", home)

	workspace, err := Workspace(DefaultStateID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, DefaultStateID)
	if workspace != want {
		t.Fatalf("workspace = %q, want %q", workspace, want)
	}
}

func TestListWorkspacesSortsAndFiltersEntries(t *testing.T) {
	stateHome := t.TempDir()
	root := filepath.Join(stateHome, "ict")
	t.Setenv("XDG_STATE_HOME", stateHome)

	for _, name := range []string{"zeta", "alpha", "plan-only", ".hidden", "bad name"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "alpha", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file-state"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "alpha"), filepath.Join(root, "linked-state")); err != nil {
		t.Fatal(err)
	}

	workspaces, err := ListWorkspaces()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(workspaces, ","), "alpha,plan-only,zeta"; got != want {
		t.Fatalf("workspaces = %q, want %q", got, want)
	}
}

func TestStateRootCanonicalizesRelativeStateHome(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv("XDG_STATE_HOME", "state home")

	root, err := StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	canonicalWorkingDirectory, err := filepath.EvalSymlinks(workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canonicalWorkingDirectory, "state home", "ict")
	if root != want || !filepath.IsAbs(root) {
		t.Fatalf("state root = %q, want absolute %q", root, want)
	}
}

func TestListWorkspaceInventoryReturnsCanonicalSortedLocations(t *testing.T) {
	stateHome := filepath.Join(t.TempDir(), "state home")
	root := filepath.Join(stateHome, "ict")
	t.Setenv("XDG_STATE_HOME", stateHome)
	for _, name := range []string{"zeta", "alpha"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	inventory, err := ListWorkspaceInventory()
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Version != 1 || !filepath.IsAbs(inventory.StateRoot) {
		t.Fatalf("inventory = %#v", inventory)
	}
	if got, want := len(inventory.Workspaces), 2; got != want {
		t.Fatalf("workspace count = %d, want %d", got, want)
	}
	for index, wantID := range []string{"alpha", "zeta"} {
		workspace := inventory.Workspaces[index]
		if workspace.ID != wantID || workspace.Path != filepath.Join(inventory.StateRoot, wantID) || !filepath.IsAbs(workspace.Path) {
			t.Fatalf("workspace %d = %#v", index, workspace)
		}
	}
}

func TestListWorkspaceInventoryMissingRootIsEmpty(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	inventory, err := ListWorkspaceInventory()
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Version != 1 || !filepath.IsAbs(inventory.StateRoot) || len(inventory.Workspaces) != 0 {
		t.Fatalf("inventory = %#v", inventory)
	}
	if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
		t.Fatalf("ListWorkspaceInventory created the state root: %v", err)
	}
}

func TestListWorkspaceInventoryRejectsInvalidLocations(t *testing.T) {
	t.Run("workspace symlink", func(t *testing.T) {
		stateHome := t.TempDir()
		root := filepath.Join(stateHome, "ict")
		t.Setenv("XDG_STATE_HOME", stateHome)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(root, "escape")); err != nil {
			t.Fatal(err)
		}

		if _, err := ListWorkspaceInventory(); err == nil || !strings.Contains(err.Error(), "symbolic links") {
			t.Fatalf("ListWorkspaceInventory error = %v", err)
		}
	})
	t.Run("state root file", func(t *testing.T) {
		stateHome := t.TempDir()
		t.Setenv("XDG_STATE_HOME", stateHome)
		if err := os.WriteFile(filepath.Join(stateHome, "ict"), nil, 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := ListWorkspaceInventory(); err == nil || !strings.Contains(err.Error(), "read Terraform state root") {
			t.Fatalf("ListWorkspaceInventory error = %v", err)
		}
	})
}

func TestListWorkspacesMissingRootIsEmptyAndNonCreating(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	workspaces, err := ListWorkspaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 0 {
		t.Fatalf("workspaces = %q, want empty", workspaces)
	}
	if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
		t.Fatalf("ListWorkspaces created the state root: %v", err)
	}
}

func TestListWorkspacesReportsRootReadErrors(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	if err := os.WriteFile(filepath.Join(stateHome, "ict"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ListWorkspaces(); err == nil || !strings.Contains(err.Error(), "read Terraform state root") {
		t.Fatalf("ListWorkspaces error = %v, want root read error", err)
	}
}

func TestWorkspaceRejectsInvalidStateID(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	for _, stateID := range []string{"", ".hidden", ".", "..", "a/b", `a\\b`, "a/../b", "naive-\u00e9", strings.Repeat("a", 129)} {
		t.Run(stateID, func(t *testing.T) {
			if _, err := Workspace(stateID); err == nil {
				t.Fatalf("Workspace(%q) succeeded", stateID)
			}
			if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
				t.Fatalf("invalid state ID created the state root: %v", err)
			}
		})
	}
}
