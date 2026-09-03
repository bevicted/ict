package config

import (
	"bytes"
	"context"
	"errors"
	"io"
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

func TestRunnerSetParsesInlineAndStdinValues(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		value string
		stdin string
		check func(t *testing.T, cfg *Config)
	}{
		{
			name:  "inline scalar",
			path:  "targets.alpha.default_region",
			value: "eu-gb",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Targets["alpha"].DefaultRegion != "eu-gb" {
					t.Fatalf("default region = %q", cfg.Targets["alpha"].DefaultRegion)
				}
			},
		},
		{
			name:  "inline list",
			path:  "targets.alpha.providers",
			value: "[classic]",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				providers := cfg.Targets["alpha"].Providers
				if len(providers) != 1 || providers[0] != ProviderClassic {
					t.Fatalf("providers = %#v", providers)
				}
			},
		},
		{
			name:  "stdin object",
			path:  "targets.alpha.endpoints",
			value: "-",
			stdin: `iam: https://replacement.example.invalid
container_service: https://containers.example.invalid
global_tagging: https://global-tagging.example.invalid
resource_management: https://resource-management.example.invalid
resource_controller: https://resource-controller.example.invalid
vpc: https://vpc.{region}.example.invalid
satellite: https://satellite.example.invalid
satellite_config: https://satellite-config.example.invalid`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Targets["alpha"].Endpoints.IAM != "https://replacement.example.invalid" {
					t.Fatalf("IAM endpoint = %q", cfg.Targets["alpha"].Endpoints.IAM)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, validConfig)
			runner := Runner{Stdin: strings.NewReader(test.stdin)}
			if err := runner.Set(path, test.path, test.value); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, cfg)
		})
	}
}

func TestRunnerSetInsertsAndPreservesUnrelatedSyntax(t *testing.T) {
	contents := strings.Replace(validConfig, "version: 1", "# top-level comment\nversion: 1", 1)
	contents = strings.Replace(contents, "    default_region: us-south", "    default_region: 'us-south' # retained style", 1)
	contents = strings.Replace(contents, "      iam: https://iam.example.invalid", "      # IAM mapping comment\n      iam: https://iam.example.invalid # retained value comment", 1)
	contents = strings.Replace(contents, "      satellite_config: https://satellite-config.example.invalid\n", "", 1)
	path := writeConfig(t, contents)

	if err := (Runner{}).Set(path, "targets.alpha.endpoints.satellite_config", "https://restored.example.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := (Runner{}).Set(path, "targets.alpha.endpoints.iam", "https://updated.example.invalid"); err != nil {
		t.Fatal(err)
	}
	newTarget := `providers: [classic]
default_region: eu-gb
endpoints:
  iam: https://iam.example.invalid
  container_service: https://containers.example.invalid
  global_tagging: https://global-tagging.example.invalid
  resource_management: https://resource-management.example.invalid
  resource_controller: https://resource-controller.example.invalid`
	if err := (Runner{}).Set(path, "targets.gamma", newTarget); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(stored)
	for _, want := range []string{
		"# top-level comment\n",
		"default_region: 'us-south' # retained style",
		"# IAM mapping comment\n",
		"iam: https://updated.example.invalid # retained value comment",
		"satellite_config: https://restored.example.invalid",
		"  gamma:\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stored config does not preserve %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "providers:") > strings.Index(text, "default_region:") || strings.Index(text, "default_region:") > strings.Index(text, "endpoints:") {
		t.Errorf("unrelated mapping order changed:\n%s", text)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerSetRejectsInvalidCandidatesWithoutChangingSource(t *testing.T) {
	completeTarget := `providers: [classic]
default_region: eu-gb
endpoints:
  iam: https://iam.example.invalid
  container_service: https://containers.example.invalid
  global_tagging: https://global-tagging.example.invalid
  resource_management: https://resource-management.example.invalid
  resource_controller: https://resource-controller.example.invalid`
	tests := []struct {
		name    string
		content string
		path    string
		value   string
		stdin   string
		want    string
	}{
		{"empty path", validConfig, "", "value", "", "invalid config path"},
		{"malformed path", validConfig, "targets..alpha", "value", "", "invalid config path"},
		{"impossible traversal", validConfig, "version.value", "value", "", "cannot traverse scalar"},
		{"unknown field", validConfig, "targets.alpha.unknown", "value", "", "decode config"},
		{"duplicate field", strings.Replace(validConfig, "version: 1", "version: 1\nversion: 1", 1), "targets.alpha.default_region", "eu-gb", "", "parse config"},
		{"extra document", validConfig + "---\nversion: 1\ntargets: {}\n", "targets.alpha.default_region", "eu-gb", "", "parse config"},
		{"incompatible type", validConfig, "version", "nope", "", "decode config"},
		{"unsupported version", validConfig, "version", "2", "", "unsupported config version"},
		{"unsupported provider", validConfig, "targets.alpha.providers", "[other]", "", "unsupported provider"},
		{"invalid target", validConfig, "targets.Alpha", completeTarget, "", "invalid target"},
		{"invalid region", validConfig, "targets.alpha.default_region", "not_a_region", "", "invalid default_region"},
		{"invalid URL", validConfig, "targets.alpha.endpoints.iam", "not-a-url", "", "invalid iam endpoint"},
		{"incomplete endpoint", validConfig, "targets.alpha.endpoints.iam", "''", "", "iam is required"},
		{"malformed stdin", validConfig, "targets.alpha.endpoints.iam", "-", "[", "parse config set value"},
		{"empty stdin", validConfig, "targets.alpha.endpoints.iam", "-", "", "value is empty"},
		{"malformed source", "targets: [", "targets.alpha.endpoints.iam", "https://replacement.example.invalid", "", "parse config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, test.content)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			err = (Runner{Stdin: strings.NewReader(test.stdin)}).Set(path, test.path, test.value)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Set() error = %v, want containing %q", err, test.want)
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, original) {
				t.Errorf("Set() changed invalid source:\nwant %q\n got %q", original, stored)
			}
			temporary, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".ict-config-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(temporary) != 0 {
				t.Errorf("Set() left temporary files: %v", temporary)
			}
		})
	}
}

func TestRunnerSetReportsMissingSourceAndUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if err := (Runner{}).Set(path, "version", "1"); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Fatalf("Set() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing config was created: %v", err)
	}

	discovered := writeConfig(t, validConfig)
	if err := (Runner{Environ: []string{"ICT_CONFIG=" + discovered}}).Set("", "targets.alpha.default_region", "eu-gb"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(discovered)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Targets["alpha"].DefaultRegion != "eu-gb" {
		t.Fatalf("discovered default region = %q", cfg.Targets["alpha"].DefaultRegion)
	}

	path = writeConfig(t, validConfig)
	if err := (Runner{}).Set(path, "targets.alpha.default_region", "eu-gb"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("config mode = %o, want 600", got)
	}
}

func TestRunnerEditUsesEditorForTerminalStdinWithRedirectedStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config directory", "config file.yaml")
	stdin := strings.NewReader("editor stdin")
	var stdout, stderr bytes.Buffer
	ctx := context.WithValue(context.Background(), "test context", "present")
	editor := &fakeEditor{run: func(ctx context.Context, gotStdin io.Reader, gotStdout, gotStderr io.Writer, name string, args ...string) error {
		if ctx.Value("test context") != "present" {
			t.Error("editor did not receive command context")
		}
		if gotStdin != stdin || gotStdout != &stdout || gotStderr != &stderr {
			t.Error("editor did not inherit configured streams")
		}
		if name != "fake-editor" || strings.Join(args, "|") != "--wait|"+path {
			t.Errorf("editor invocation = %q %q", name, args)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("created config mode = %o, want 600", info.Mode().Perm())
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if parent.Mode().Perm() != 0o700 {
			t.Errorf("created parent mode = %o, want 700", parent.Mode().Perm())
		}
		return os.WriteFile(path, []byte("malformed: [\n"), 0o600)
	}}
	stdinFD := int(os.Stdin.Fd())
	runner := Runner{
		Stdin:   stdin,
		Stdout:  &stdout,
		Stderr:  &stderr,
		Environ: []string{"EDITOR=fake-editor --wait"},
		IsTerminal: func(fd int) bool {
			if fd != stdinFD {
				t.Errorf("terminal check used file descriptor %d, want stdin %d", fd, stdinFD)
			}
			return true
		},
		Process: editor,
	}
	if err := runner.Edit(ctx, path); err != nil {
		t.Fatal(err)
	}
	if !editor.called {
		t.Error("terminal stdin with redirected stdout did not invoke editor")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "malformed: [\n"; got != want {
		t.Errorf("editor contents = %q, want %q", got, want)
	}
	if _, err := Load(path); err == nil {
		t.Error("malformed editor output unexpectedly validated")
	}
}

func TestRunnerEditEditorInheritsEnvironmentAndStreams(t *testing.T) {
	directory := t.TempDir()
	script := filepath.Join(directory, "editor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$EDITOR_MARKER\" > \"$2\"\nprintf 'editor stdout'\nprintf 'editor stderr' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config with spaces.yaml")
	var stdout, stderr bytes.Buffer
	runner := Runner{
		Stdin:    strings.NewReader("ignored"),
		Stdout:   &stdout,
		Stderr:   &stderr,
		Environ:  []string{"EDITOR=" + script + " --argument", "EDITOR_MARKER=invalid: ["},
		Terminal: func() bool { return true },
	}
	if err := runner.Edit(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "invalid: ["; got != want {
		t.Errorf("editor environment output = %q, want %q", got, want)
	}
	if got := stdout.String(); got != "editor stdout" {
		t.Errorf("editor stdout = %q", got)
	}
	if got := stderr.String(); got != "editor stderr" {
		t.Errorf("editor stderr = %q", got)
	}
}

func TestRunnerEditReportsEditorFailuresWithoutRollback(t *testing.T) {
	t.Run("missing EDITOR", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		err := (Runner{Environ: []string{}, Terminal: func() bool { return true }}).Edit(context.Background(), path)
		if err == nil || !strings.Contains(err.Error(), "EDITOR is not set") {
			t.Fatalf("Edit() error = %v", err)
		}
	})
	t.Run("process start failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		err := (Runner{Environ: []string{"EDITOR=not-an-editor"}, Terminal: func() bool { return true }}).Edit(context.Background(), path)
		if err == nil || !strings.Contains(err.Error(), "not-an-editor") {
			t.Fatalf("Edit() error = %v", err)
		}
	})
	t.Run("editor failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		editor := &fakeEditor{run: func(_ context.Context, _ io.Reader, _ io.Writer, _ io.Writer, _ string, args ...string) error {
			if err := os.WriteFile(args[len(args)-1], []byte("still malformed: ["), 0o600); err != nil {
				return err
			}
			return errors.New("editor failed")
		}}
		err := (Runner{Environ: []string{"EDITOR=fake-editor"}, Terminal: func() bool { return true }, Process: editor}).Edit(context.Background(), path)
		if err == nil || !strings.Contains(err.Error(), "editor failed") {
			t.Fatalf("Edit() error = %v", err)
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if got, want := string(contents), "still malformed: ["; got != want {
			t.Errorf("editor changes = %q, want %q", got, want)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		editor := &fakeEditor{run: func(context.Context, io.Reader, io.Writer, io.Writer, string, ...string) error {
			return context.Canceled
		}}
		err := (Runner{Environ: []string{"EDITOR=fake-editor"}, Terminal: func() bool { return true }, Process: editor}).Edit(context.Background(), path)
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Edit() error = %v", err)
		}
	})
}

func TestRunnerEditReplacesNonTerminalInputExactly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config directory", "config file.yaml")
	contents := []byte("malformed: [\n# retained exactly\n")
	editor := &fakeEditor{}
	runner := Runner{
		Stdin:    bytes.NewReader(contents),
		Terminal: func() bool { return false },
		Process:  editor,
	}
	if err := runner.Edit(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if editor.called {
		t.Error("non-terminal input invoked editor")
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, contents) {
		t.Errorf("stored bytes = %q, want %q", stored, contents)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", info.Mode().Perm())
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm() != 0o700 {
		t.Errorf("parent mode = %o, want 700", parent.Mode().Perm())
	}
}

func TestRunnerEditUsesDiscoveryPrecedence(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "explicit.yaml")
	environment := filepath.Join(t.TempDir(), "environment.yaml")
	configHome := t.TempDir()
	xdg := filepath.Join(configHome, "ict", "config.yaml")
	tests := []struct {
		name    string
		config  string
		environ []string
		path    string
	}{
		{"explicit", explicit, []string{"ICT_CONFIG=" + environment, "XDG_CONFIG_HOME=" + configHome}, explicit},
		{"ICT_CONFIG", "", []string{"ICT_CONFIG=" + environment, "XDG_CONFIG_HOME=" + configHome}, environment},
		{"XDG", "", []string{"XDG_CONFIG_HOME=" + configHome}, xdg},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := Runner{Stdin: strings.NewReader("invalid: ["), Environ: test.environ, Terminal: func() bool { return false }}
			if err := runner.Edit(context.Background(), test.config); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(contents), "invalid: ["; got != want {
				t.Errorf("stored bytes = %q, want %q", got, want)
			}
		})
	}
}

func TestRunnerEditRejectsEmptyInputWithoutChangingDestination(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	existing := writeConfig(t, "keep this unchanged")
	for name, path := range map[string]string{"missing": missing, "existing": existing} {
		t.Run(name, func(t *testing.T) {
			var original []byte
			if name == "existing" {
				var err error
				original, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := (Runner{Stdin: strings.NewReader(""), Terminal: func() bool { return false }}).Edit(context.Background(), path)
			if err == nil || !strings.Contains(err.Error(), "standard input is empty") {
				t.Fatalf("Edit() error = %v", err)
			}
			if name == "missing" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("empty input created destination: %v", err)
				}
			} else if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
				t.Errorf("empty input changed destination: %q, %v", got, err)
			}
			temporary, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".ict-config-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(temporary) != 0 {
				t.Errorf("empty input left temporary files: %v", temporary)
			}
		})
	}
}

func TestRunnerEditCleansTemporaryFileAfterAtomicWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := (Runner{Stdin: strings.NewReader("invalid: ["), Terminal: func() bool { return false }}).Edit(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "replace config") {
		t.Fatalf("Edit() error = %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("atomic write changed destination: info=%v, err=%v", info, statErr)
	}
	temporary, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".ict-config-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporary) != 0 {
		t.Errorf("atomic write failure left temporary files: %v", temporary)
	}
}

type fakeEditor struct {
	called bool
	run    func(context.Context, io.Reader, io.Writer, io.Writer, string, ...string) error
}

func (f *fakeEditor) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	f.called = true
	if f.run == nil {
		return nil
	}
	return f.run(ctx, stdin, stdout, stderr, name, args...)
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }
