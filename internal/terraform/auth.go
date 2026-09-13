package terraform

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed auth-assets/main.tf auth-assets/variables.tf auth-assets/.terraform.lock.hcl
var authAssets embed.FS

// MaterializeAuth writes the isolated public-auth Terraform root.
func MaterializeAuth(workspace string) error {
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return fmt.Errorf("create auth Terraform workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		return fmt.Errorf("protect auth Terraform workspace: %w", err)
	}
	for source, destination := range map[string]string{
		"auth-assets/main.tf":             "main.tf",
		"auth-assets/variables.tf":        "variables.tf",
		"auth-assets/.terraform.lock.hcl": ".terraform.lock.hcl",
	} {
		contents, err := fs.ReadFile(authAssets, source)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", source, err)
		}
		if err := atomicWrite(filepath.Join(workspace, destination), contents); err != nil {
			return err
		}
	}
	return nil
}
