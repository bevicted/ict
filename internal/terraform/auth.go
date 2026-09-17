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

//go:embed auth-cleanup-assets/main.tf auth-cleanup-assets/variables.tf auth-cleanup-assets/.terraform.lock.hcl
var authCleanupAssets embed.FS

// MaterializeAuth writes the isolated public-auth Terraform root.
func MaterializeAuth(workspace string) error {
	return materializeAuthRoot(workspace, authAssets, "auth-assets")
}

// MaterializeAuthCleanup writes the cluster-independent companion-state cleanup root.
func MaterializeAuthCleanup(workspace string) error {
	return materializeAuthRoot(workspace, authCleanupAssets, "auth-cleanup-assets")
}

func materializeAuthRoot(workspace string, assets fs.FS, root string) error {
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return fmt.Errorf("create auth Terraform workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		return fmt.Errorf("protect auth Terraform workspace: %w", err)
	}
	for source, destination := range map[string]string{
		root + "/main.tf":             "main.tf",
		root + "/variables.tf":        "variables.tf",
		root + "/.terraform.lock.hcl": ".terraform.lock.hcl",
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
