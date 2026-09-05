// Package terraform materializes and invokes the embedded Terraform configuration.
package terraform

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

//go:embed assets/main.tf assets/variables.tf assets/.terraform.lock.hcl assets/cluster-name.tftest.hcl assets/satellite-topology.tftest.hcl assets/vpc-reuse.tftest.hcl
var assets embed.FS

const (
	TFVarsName  = ".cluster/cluster.tfvars.json"
	ContextName = ".cluster/context.json"
)

const DefaultStateID = "default"

var stateIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// StateRoot returns the directory containing ICT state workspaces.
func StateRoot() (string, error) {
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(stateHome, "ict"), nil
}

// Workspace returns the selected Terraform workspace without creating it.
func Workspace(stateID string) (string, error) {
	if !stateIDPattern.MatchString(stateID) {
		return "", fmt.Errorf("invalid state ID %q: must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}", stateID)
	}
	root, err := StateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, stateID), nil
}

// ListWorkspaces returns the valid immediate workspace directories in lexical order.
func ListWorkspaces() ([]string, error) {
	root, err := StateRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Terraform state root: %w", err)
	}

	workspaces := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !stateIDPattern.MatchString(entry.Name()) {
			continue
		}
		workspaces = append(workspaces, entry.Name())
	}
	return workspaces, nil
}

// Materialize writes the canonical Terraform files without altering state files.
func Materialize(workspace string) error {
	if err := os.MkdirAll(filepath.Join(workspace, ".cluster"), 0o700); err != nil {
		return fmt.Errorf("create Terraform workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		return fmt.Errorf("protect Terraform workspace: %w", err)
	}
	if err := os.Chmod(filepath.Join(workspace, ".cluster"), 0o700); err != nil {
		return fmt.Errorf("protect Terraform runtime directory: %w", err)
	}
	for source, destination := range map[string]string{
		"assets/main.tf":                       "main.tf",
		"assets/variables.tf":                  "variables.tf",
		"assets/.terraform.lock.hcl":           ".terraform.lock.hcl",
		"assets/cluster-name.tftest.hcl":       "cluster-name.tftest.hcl",
		"assets/satellite-topology.tftest.hcl": "satellite-topology.tftest.hcl",
		"assets/vpc-reuse.tftest.hcl":          "vpc-reuse.tftest.hcl",
	} {
		contents, err := fs.ReadFile(assets, source)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", source, err)
		}
		if err := atomicWrite(filepath.Join(workspace, destination), contents); err != nil {
			return err
		}
	}
	return nil
}

// AtomicWrite replaces a private runtime file only after its complete content is written.
func AtomicWrite(path string, contents []byte) error {
	if err := atomicWrite(path, contents); err != nil {
		return fmt.Errorf("write runtime file: %w", err)
	}
	return nil
}

func atomicWrite(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".ict-")
	if err != nil {
		return fmt.Errorf("create temporary runtime file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary runtime file: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write runtime file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close runtime file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace runtime file: %w", err)
	}
	return os.Chmod(path, 0o600)
}
