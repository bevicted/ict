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
			want := filepath.Join(stateHome, "ict", stateID)
			if workspace != want {
				t.Fatalf("workspace = %q, want %q", workspace, want)
			}
			if _, err := os.Stat(filepath.Join(stateHome, "ict")); !os.IsNotExist(err) {
				t.Fatalf("Workspace created the state root: %v", err)
			}
		})
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
	want := filepath.Join(home, ".local", "state", "ict", DefaultStateID)
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
