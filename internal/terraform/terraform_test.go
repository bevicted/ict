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
