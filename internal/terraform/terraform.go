// Package terraform materializes the embedded Terraform configuration.
package terraform

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

//go:embed assets/main.tf assets/variables.tf assets/.terraform.lock.hcl
var assets embed.FS

const (
	TFVarsName  = ".cluster/cluster.tfvars.json"
	ContextName = ".cluster/context.json"
	PlanName    = ".cluster/create.tfplan"
)

var stateIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidateStateID verifies that an opaque lifecycle identifier is safe to serialize.
func ValidateStateID(stateID string) error {
	if !stateIDPattern.MatchString(stateID) {
		return fmt.Errorf("invalid state ID %q: must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}", stateID)
	}
	return nil
}

// Materialize writes the canonical Terraform files without altering backend state files.
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
		"assets/main.tf":             "main.tf",
		"assets/variables.tf":        "variables.tf",
		"assets/.terraform.lock.hcl": ".terraform.lock.hcl",
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
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect runtime file: %w", err)
	}
	return nil
}
