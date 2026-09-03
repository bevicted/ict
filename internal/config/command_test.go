package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestRunnerShowPrintsEffectiveConfig(t *testing.T) {
	path := writeConfig(t, validConfig)
	var output bytes.Buffer
	runner := Runner{
		Stdout: &output,
		Environ: []string{
			"ICT_CONFIG=" + path,
			"IBMCLOUD_IAM_API_ENDPOINT=https://override.example.invalid",
		},
	}
	if err := runner.Show(""); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"version: 1\n",
		"  alpha:\n",
		"  beta:\n",
		"iam: https://override.example.invalid\n",
		"vpc: https://vpc.us-south.example.invalid\n",
		"vpc: https://vpc.eu-gb.example.invalid\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("show output does not contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "{region}") {
		t.Errorf("show output contains an unexpanded VPC template:\n%s", got)
	}
	if strings.Index(got, "  alpha:\n") > strings.Index(got, "  beta:\n") {
		t.Errorf("show output is not deterministically ordered:\n%s", got)
	}
}

func TestRunnerGetPrintsScalarsAndCollections(t *testing.T) {
	path := writeConfig(t, validConfig)
	tests := map[string]struct {
		path string
		want string
	}{
		"string":      {path: "targets.alpha.endpoints.iam", want: "https://override.example.invalid\n"},
		"integer":     {path: "version", want: "1\n"},
		"list":        {path: "targets.alpha.providers", want: "- vpc-gen2\n- classic\n- satellite\n"},
		"list scalar": {path: "targets.alpha.providers.0", want: "vpc-gen2\n"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			runner := Runner{
				Stdout: &output,
				Environ: []string{
					"ICT_CONFIG=" + path,
					"IBMCLOUD_IAM_API_ENDPOINT=https://override.example.invalid",
				},
			}
			if err := runner.Get("", test.path); err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != test.want {
				t.Errorf("get output = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunnerGetPrintsMapsAsYAML(t *testing.T) {
	path := writeConfig(t, validConfig)
	var output bytes.Buffer
	if err := (Runner{Stdout: &output}).Get(path, "targets.alpha.endpoints"); err != nil {
		t.Fatal(err)
	}
	var endpoints Endpoints
	if err := yaml.Unmarshal(output.Bytes(), &endpoints); err != nil {
		t.Fatalf("get output is not valid YAML: %v", err)
	}
	if endpoints.IAM != "https://iam.example.invalid" || endpoints.VPC != "https://vpc.us-south.example.invalid" {
		t.Fatalf("endpoints = %#v", endpoints)
	}
}

func TestRunnerUsesDiscoveryPrecedenceFromInjectedEnvironment(t *testing.T) {
	explicit := writeConfig(t, validConfig)
	environment := writeConfig(t, strings.Replace(validConfig, "alpha:", "environment:", 1))
	configHome := t.TempDir()
	xdgPath := filepath.Join(configHome, "ict", "config.yaml")
	if err := os.Mkdir(filepath.Dir(xdgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdgPath, []byte(strings.Replace(validConfig, "alpha:", "xdg:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		config  string
		environ []string
		want    string
	}{
		"explicit": {
			config: explicit,
			environ: []string{
				"ICT_CONFIG=" + environment,
				"XDG_CONFIG_HOME=" + configHome,
			},
			want: "us-south\n",
		},
		"ICT_CONFIG": {
			environ: []string{
				"ICT_CONFIG=" + environment,
				"XDG_CONFIG_HOME=" + configHome,
			},
			want: "us-south\n",
		},
		"XDG": {
			environ: []string{
				"ICT_CONFIG=",
				"XDG_CONFIG_HOME=" + configHome,
			},
			want: "us-south\n",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			runner := Runner{Stdout: &output, Environ: test.environ}
			if err := runner.Get(test.config, "targets."+map[string]string{"explicit": "alpha", "ICT_CONFIG": "environment", "XDG": "xdg"}[name]+".default_region"); err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != test.want {
				t.Errorf("get output = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunnerReadErrorsDoNotWriteOutput(t *testing.T) {
	invalidPath := writeConfig(t, strings.Replace(validConfig, "https://iam.example.invalid", "not a URL", 1))
	malformedPath := writeConfig(t, "targets: [")
	multipleDocumentsPath := writeConfig(t, validConfig+"---\nversion: 1\ntargets: {}\n")
	validPath := writeConfig(t, validConfig)
	tests := map[string]struct {
		config  string
		path    string
		environ []string
		want    string
	}{
		"missing file":       {config: filepath.Join(t.TempDir(), "missing.yaml"), want: "open config"},
		"invalid config":     {config: invalidPath, want: "validate config"},
		"malformed config":   {config: malformedPath, want: "decode config"},
		"multiple documents": {config: multipleDocumentsPath, want: "multiple YAML documents"},
		"invalid override": {
			config:  validPath,
			environ: []string{"IBMCLOUD_IAM_API_ENDPOINT=not-a-url"},
			want:    "resolve target",
		},
		"empty path":         {config: validPath, path: "", want: "invalid config path"},
		"empty path segment": {config: validPath, path: "targets..alpha", want: "invalid config path"},
		"missing key":        {config: validPath, path: "targets.alpha.missing", want: "does not exist"},
		"scalar traversal":   {config: validPath, path: "version.value", want: "cannot traverse scalar"},
		"invalid index":      {config: validPath, path: "targets.alpha.providers.nope", want: "does not contain index"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			runner := Runner{Stdout: &output, Environ: test.environ}
			err := runner.Get(test.config, test.path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Get() error = %v, want containing %q", err, test.want)
			}
			if got := output.String(); got != "" {
				t.Errorf("Get() wrote partial output %q", got)
			}
		})
	}
}

func TestRunnerReportsOutputErrors(t *testing.T) {
	path := writeConfig(t, validConfig)
	writer := errWriter{err: errors.New("broken pipe")}
	if err := (Runner{Stdout: writer}).Show(path); err == nil || !strings.Contains(err.Error(), "write effective config") {
		t.Fatalf("Show() error = %v", err)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }
