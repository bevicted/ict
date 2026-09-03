package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `version: 1
targets:
  alpha:
    providers: [vpc-gen2, classic, satellite]
    default_region: us-south
    endpoints:
      iam: https://iam.example.invalid
      container_service: https://containers.example.invalid
      global_tagging: https://global-tagging.example.invalid
      resource_management: https://resource-management.example.invalid
      resource_controller: https://resource-controller.example.invalid
      vpc: https://vpc.{region}.example.invalid
      satellite: https://satellite.example.invalid
      satellite_config: https://satellite-config.example.invalid
  beta:
    providers: [classic]
    default_region: eu-gb
    endpoints:
      iam: https://iam.example.invalid
      container_service: https://containers.example.invalid
      global_tagging: https://global-tagging.example.invalid
      resource_management: https://resource-management.example.invalid
      resource_controller: https://resource-controller.example.invalid
      vpc: https://vpc.{region}.example.invalid
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidMultiProviderConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(cfg.Targets))
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]struct {
		path    func(t *testing.T) string
		content string
		want    string
	}{
		"missing file": {
			path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.yaml") },
			want: "open config",
		},
		"unreadable directory": {
			path: func(t *testing.T) string { return t.TempDir() },
			want: "decode config",
		},
		"empty":                        {content: "", want: "is empty"},
		"unsupported version":          {content: strings.Replace(validConfig, "version: 1", "version: 2", 1), want: "unsupported config version"},
		"unknown field":                {content: strings.Replace(validConfig, "version: 1", "version: 1\nunknown: value", 1), want: "decode config"},
		"duplicate field":              {content: strings.Replace(validConfig, "version: 1", "version: 1\nversion: 1", 1), want: "decode config"},
		"multiple documents":           {content: validConfig + "---\nversion: 1\ntargets: {}\n", want: "multiple YAML documents"},
		"invalid target":               {content: strings.Replace(validConfig, "  alpha:", "  Alpha:", 1), want: "invalid target"},
		"unsupported provider":         {content: strings.Replace(validConfig, "[classic]", "[other]", 1), want: "unsupported provider"},
		"invalid region":               {content: strings.Replace(validConfig, "default_region: eu-gb", "default_region: not_a_region", 1), want: "invalid default_region"},
		"malformed URL":                {content: strings.Replace(validConfig, "https://iam.example.invalid", "not a URL", 1), want: "invalid iam endpoint"},
		"invalid VPC template":         {content: strings.Replace(validConfig, "https://vpc.{region}.example.invalid", "https://vpc.example.invalid", 1), want: "invalid vpc endpoint template"},
		"incomplete provider endpoint": {content: strings.Replace(validConfig, "      satellite_config: https://satellite-config.example.invalid\n", "", 1), want: "satellite_config is required"},
		"unselected profile invalid":   {content: strings.Replace(validConfig, "default_region: eu-gb", "default_region: invalid", 1), want: "invalid default_region"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, test.content)
			if test.path != nil {
				path = test.path(t)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestDiscoverPathPrecedence(t *testing.T) {
	t.Setenv("ICT_CONFIG", "/environment/config.yaml")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	path, err := DiscoverPath("/explicit/config.yaml")
	if err != nil || path != "/explicit/config.yaml" {
		t.Fatalf("explicit path = %q, %v", path, err)
	}
	path, err = DiscoverPath("")
	if err != nil || path != "/environment/config.yaml" {
		t.Fatalf("environment path = %q, %v", path, err)
	}
	t.Setenv("ICT_CONFIG", "")
	path, err = DiscoverPath("")
	if err != nil || path != "/xdg/ict/config.yaml" {
		t.Fatalf("XDG path = %q, %v", path, err)
	}
}

func TestDiscoverPathUsesHomeFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ICT_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)
	path, err := DiscoverPath("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "ict", "config.yaml")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

func TestResolveTargetUsesOverridesWithoutMutatingEnvironment(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	defaultResolved, err := cfg.ResolveTarget("alpha", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultResolved.Endpoints.VPC; got != "https://vpc.us-south.example.invalid" {
		t.Fatalf("default VPC endpoint = %q", got)
	}
	t.Setenv("IBMCLOUD_IAM_API_ENDPOINT", "https://parent.example.invalid")
	resolved, err := cfg.ResolveTarget("alpha", []string{
		"IBMCLOUD_IAM_API_ENDPOINT=https://override.example.invalid",
		"IBMCLOUD_IS_NG_API_ENDPOINT=https://override.us-south.example.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resolved.Endpoints.IAM; got != "https://override.example.invalid" {
		t.Fatalf("IAM endpoint = %q", got)
	}
	if got := resolved.Endpoints.VPC; got != "https://override.us-south.example.invalid" {
		t.Fatalf("VPC endpoint = %q", got)
	}
	if got := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT"); got != "https://parent.example.invalid" {
		t.Fatalf("parent environment changed to %q", got)
	}
	regional, err := cfg.ResolveTargetForRegion("alpha", "eu-gb", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := regional.Endpoints.VPC; got != "https://vpc.eu-gb.example.invalid" {
		t.Fatalf("regional VPC endpoint = %q", got)
	}
}

func TestResolveTargetRejectsInvalidOverridesAndSortsTargets(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.ResolveTarget("alpha", []string{"IBMCLOUD_IAM_API_ENDPOINT=not-a-url"})
	if err == nil || !strings.Contains(err.Error(), "invalid iam endpoint") {
		t.Fatalf("ResolveTarget() error = %v", err)
	}
	_, err = cfg.Target("missing")
	if err == nil || !strings.Contains(err.Error(), "available: alpha, beta") {
		t.Fatalf("Target() error = %v", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q): %v", path, err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("example targets = %d, want 1", len(cfg.Targets))
	}
	for name, target := range cfg.Targets {
		if name != "example" {
			t.Fatalf("example target = %q, want generic name", name)
		}
		for _, endpoint := range []string{
			target.Endpoints.IAM,
			target.Endpoints.ContainerService,
			target.Endpoints.GlobalTagging,
			target.Endpoints.ResourceManagement,
			target.Endpoints.ResourceController,
			strings.ReplaceAll(target.Endpoints.VPC, "{region}", "us-south"),
			target.Endpoints.Satellite,
			target.Endpoints.SatelliteConfig,
		} {
			parsed, err := url.Parse(endpoint)
			if err != nil || parsed.Hostname() == "" || !strings.HasSuffix(parsed.Hostname(), ".example.invalid") {
				t.Fatalf("example endpoint %q is not reserved", endpoint)
			}
		}
	}
}
