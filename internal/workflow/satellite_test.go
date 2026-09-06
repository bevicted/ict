package workflow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSatelliteValidationRemainsPreflight(t *testing.T) {
	inputs := configuredInputs(t)
	inputs.Provider = "satellite"
	inputs.Platform = "kubernetes"
	inputs.AutoApprove = true
	content, err := os.ReadFile(inputs.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), "[vpc-gen2]", "[vpc-gen2, satellite]", 1))
	content = []byte(strings.Replace(string(content), "      vpc: https://vpc.{region}.example.invalid\n", "      vpc: https://vpc.{region}.example.invalid\n      satellite: https://satellite.example.invalid\n      satellite_config: https://satellite-config.example.invalid\n", 1))
	if err := os.WriteFile(inputs.ConfigPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(t.TempDir(), "workspace")
	fake := &fakeTerraform{}
	runner := newRunner(workspace, fake)
	if err := runner.Create(context.Background(), inputs); err == nil || !strings.Contains(err.Error(), "requires the openshift platform") {
		t.Fatalf("Satellite preflight error = %v", err)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("Satellite preflight created workspace: %v", err)
	}
}
