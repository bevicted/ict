// Package terraform materializes and invokes the embedded Terraform configuration.
package terraform

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed assets/main.tf assets/variables.tf assets/.terraform.lock.hcl assets/cluster-name.tftest.hcl assets/satellite-topology.tftest.hcl
var assets embed.FS

const (
	TFVarsName  = ".cluster/cluster.tfvars.json"
	ContextName = ".cluster/context.json"
)

// Workspace returns the one active Terraform workspace for the current user.
func Workspace() (string, error) {
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(stateHome, "ict", "terraform"), nil
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
