package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/bevicted/ict/internal/prompt"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// ProcessRunner is the subprocess seam used by config commands that need an editor.
type ProcessRunner interface {
	Run(context.Context, io.Reader, io.Writer, io.Writer, string, ...string) error
}

// Runner wires command I/O and environment dependencies for config commands.
type Runner struct {
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Environ  []string
	Terminal func() bool
	Process  ProcessRunner
}

// Show writes the complete effective configuration as canonical YAML.
func (r Runner) Show(configPath string) error {
	cfg, err := r.effective(configPath)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode effective config: %w", err)
	}
	if _, err := r.stdout().Write(data); err != nil {
		return fmt.Errorf("write effective config: %w", err)
	}
	return nil
}

// Get writes the effective value at a dot-separated path.
func (r Runner) Get(configPath, path string) error {
	cfg, err := r.effective(configPath)
	if err != nil {
		return err
	}
	value, err := valueAt(cfg, path)
	if err != nil {
		return err
	}
	if isScalar(value) {
		if _, err := fmt.Fprintln(r.stdout(), value); err != nil {
			return fmt.Errorf("write effective config value: %w", err)
		}
		return nil
	}
	data, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode effective config value: %w", err)
	}
	if _, err := r.stdout().Write(data); err != nil {
		return fmt.Errorf("write effective config value: %w", err)
	}
	return nil
}

// Edit updates the discovered configuration from an editor or standard input without validation.
func (r Runner) Edit(ctx context.Context, configPath string) error {
	path, err := DiscoverPathFromEnvironment(configPath, r.environment())
	if err != nil {
		return fmt.Errorf("discover config: %w", err)
	}
	if r.terminal() {
		return r.editWithEditor(ctx, path)
	}
	return r.replaceFromStdin(path)
}

func (r Runner) editWithEditor(ctx context.Context, path string) error {
	if err := prepareConfigPath(path); err != nil {
		return err
	}

	editor := strings.Fields(environmentValue(r.environment(), "EDITOR"))
	if len(editor) == 0 {
		return fmt.Errorf("edit config %q: EDITOR is not set", path)
	}
	args := append(editor[1:], path)
	var err error
	if r.Process != nil {
		err = r.Process.Run(ctx, r.stdin(), r.stdout(), r.stderr(), editor[0], args...)
	} else {
		err = runEditor(ctx, r.environment(), r.stdin(), r.stdout(), r.stderr(), editor[0], args...)
	}
	if err != nil {
		return fmt.Errorf("edit config %q with editor %q: %w", path, editor[0], err)
	}
	return nil
}

func (r Runner) replaceFromStdin(path string) error {
	contents, err := io.ReadAll(r.stdin())
	if err != nil {
		return fmt.Errorf("read config edit from stdin: %w", err)
	}
	if len(contents) == 0 {
		return fmt.Errorf("edit config %q: standard input is empty", path)
	}
	if err := prepareConfigParent(path); err != nil {
		return err
	}
	if err := persistConfig(path, contents); err != nil {
		return err
	}
	return nil
}

func prepareConfigPath(path string) error {
	if err := prepareConfigParent(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create config %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close config %q: %w", path, err)
	}
	return nil
}

func prepareConfigParent(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory for %q: %w", path, err)
	}
	return nil
}

func runEditor(ctx context.Context, environ []string, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- $EDITOR intentionally selects the editor.
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = environ
	if err := command.Run(); err != nil {
		return err
	}
	return nil
}

// Set updates a stored configuration value only when the complete result validates.
func (r Runner) Set(configPath, path, value string) error {
	configPath, err := DiscoverPathFromEnvironment(configPath, r.environment())
	if err != nil {
		return fmt.Errorf("discover config: %w", err)
	}
	source, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %q: %w", configPath, err)
	}

	valueSource := []byte(value)
	if value == "-" {
		valueSource, err = io.ReadAll(r.stdin())
		if err != nil {
			return fmt.Errorf("read config set value from stdin: %w", err)
		}
	}
	valueNode, err := parseSetValue(valueSource)
	if err != nil {
		return err
	}
	parts, err := configPathParts(path)
	if err != nil {
		return err
	}
	file, err := parseSetSource(source)
	if err != nil {
		return fmt.Errorf("parse config %q: %w", configPath, err)
	}
	if err := replaceOrInsert(file, parts, valueNode); err != nil {
		return fmt.Errorf("set config path %q: %w", path, err)
	}

	candidate := []byte(file.String())
	if _, err := Decode(strings.NewReader(string(candidate))); err != nil {
		return fmt.Errorf("validate config set candidate: %w", err)
	}
	if err := persistConfig(configPath, candidate); err != nil {
		return err
	}
	return nil
}

func parseSetSource(source []byte) (*ast.File, error) {
	file, err := parser.ParseBytes(source, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if len(file.Docs) != 1 || file.Docs[0].Body == nil {
		return nil, fmt.Errorf("source must contain exactly one YAML document")
	}
	return file, nil
}

func parseSetValue(source []byte) (ast.Node, error) {
	if len(strings.TrimSpace(string(source))) == 0 {
		return nil, fmt.Errorf("config set value is empty")
	}
	file, err := parser.ParseBytes(source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse config set value: %w", err)
	}
	if len(file.Docs) != 1 || file.Docs[0].Body == nil {
		return nil, fmt.Errorf("config set value must contain exactly one YAML document")
	}
	return file.Docs[0].Body, nil
}

func configPathParts(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("invalid config path %q", path)
	}
	parts := strings.Split(path, ".")
	if slices.Contains(parts, "") {
		return nil, fmt.Errorf("invalid config path %q", path)
	}
	return parts, nil
}

func replaceOrInsert(file *ast.File, parts []string, value ast.Node) error {
	current := file.Docs[0].Body
	path := (&yaml.PathBuilder{}).Root()
	for index, part := range parts {
		switch node := current.(type) {
		case *ast.MappingNode:
			entry := mappingValue(node, part)
			if entry == nil {
				addition, err := nestedMapping(parts[index:], value)
				if err != nil {
					return err
				}
				if err := path.Build().MergeFromNode(file, addition.Docs[0]); err != nil {
					return fmt.Errorf("insert missing value: %w", err)
				}
				return nil
			}
			current = entry.Value
			path = path.Child(part)
		case *ast.SequenceNode:
			sequenceIndex, err := strconv.ParseUint(part, 10, 0)
			if err != nil || sequenceIndex >= uint64(len(node.Values)) {
				return fmt.Errorf("cannot traverse index %q", part)
			}
			current = node.Values[sequenceIndex]
			path = path.Index(uint(sequenceIndex))
		default:
			return fmt.Errorf("cannot traverse scalar %q", part)
		}
	}
	if value.GetComment() == nil && current.GetComment() != nil {
		if err := value.SetComment(current.GetComment()); err != nil {
			return fmt.Errorf("preserve value comment: %w", err)
		}
	}
	if err := path.Build().ReplaceWithNode(file, value); err != nil {
		return fmt.Errorf("replace value: %w", err)
	}
	return nil
}

func mappingValue(node *ast.MappingNode, wanted string) *ast.MappingValueNode {
	for _, entry := range node.Values {
		key := entry.Key.GetToken().Value
		if decoded, err := strconv.Unquote(key); err == nil {
			key = decoded
		} else if len(key) >= 2 && key[0] == '\'' && key[len(key)-1] == '\'' {
			key = key[1 : len(key)-1]
		}
		if key == wanted {
			return entry
		}
	}
	return nil
}

func nestedMapping(parts []string, value ast.Node) (*ast.File, error) {
	source := value.String()
	for index := len(parts) - 1; index >= 0; index-- {
		key, err := yaml.Marshal(parts[index])
		if err != nil {
			return nil, fmt.Errorf("encode config path key: %w", err)
		}
		keyText := strings.TrimSpace(string(key))
		if _, scalar := value.(ast.ScalarNode); scalar || strings.HasPrefix(source, "[") || strings.HasPrefix(source, "{") {
			source = keyText + ": " + source
		} else {
			source = keyText + ":\n" + indentYAML(source)
		}
		value = nil
	}
	file, err := parser.ParseBytes([]byte(source), parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("construct missing config path: %w", err)
	}
	return file, nil
}

func indentYAML(source string) string {
	return "  " + strings.ReplaceAll(source, "\n", "\n  ")
}

func persistConfig(path string, contents []byte) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".ict-config-*")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	temporaryPath := file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set temporary config file permissions: %w", err)
	}
	if _, err = file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary config file: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary config file: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close temporary config file: %w", err)
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config %q: %w", path, err)
	}
	return nil
}

func (r Runner) effective(configPath string) (*Config, error) {
	path, err := DiscoverPathFromEnvironment(configPath, r.environment())
	if err != nil {
		return nil, fmt.Errorf("discover config: %w", err)
	}
	stored, err := Load(path)
	if err != nil {
		return nil, err
	}
	effective := &Config{Version: stored.Version, Targets: make(map[string]Target, len(stored.Targets))}
	for name := range stored.Targets {
		resolved, err := stored.ResolveTarget(name, r.environment())
		if err != nil {
			return nil, fmt.Errorf("resolve target %q: %w", name, err)
		}
		effective.Targets[name] = resolved.Target
	}
	return effective, nil
}

func (r Runner) environment() []string {
	if r.Environ != nil {
		return r.Environ
	}
	return os.Environ()
}

func (r Runner) stdin() io.Reader {
	if r.Stdin != nil {
		return r.Stdin
	}
	return os.Stdin
}

func (r Runner) stdout() io.Writer {
	if r.Stdout != nil {
		return r.Stdout
	}
	return os.Stdout
}

func (r Runner) stderr() io.Writer {
	if r.Stderr != nil {
		return r.Stderr
	}
	return os.Stderr
}

func valueAt(cfg *Config, path string) (any, error) {
	if path == "" {
		return nil, fmt.Errorf("invalid config path %q", path)
	}
	parts := strings.Split(path, ".")
	if slices.Contains(parts, "") {
		return nil, fmt.Errorf("invalid config path %q", path)
	}

	value := reflect.ValueOf(cfg)
	for _, part := range parts {
		for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return nil, fmt.Errorf("config path %q does not exist", path)
			}
			value = value.Elem()
		}
		switch value.Kind() {
		case reflect.Struct:
			field, found := yamlField(value, part)
			if !found {
				return nil, fmt.Errorf("config path %q does not exist at %q", path, part)
			}
			value = field
		case reflect.Map:
			if value.Type().Key().Kind() != reflect.String {
				return nil, fmt.Errorf("config path %q cannot traverse %q", path, part)
			}
			entry := value.MapIndex(reflect.ValueOf(part).Convert(value.Type().Key()))
			if !entry.IsValid() {
				return nil, fmt.Errorf("config path %q does not exist at %q", path, part)
			}
			value = entry
		case reflect.Slice, reflect.Array:
			index, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("config path %q does not contain index %q: %w", path, part, err)
			}
			if index < 0 || index >= value.Len() {
				return nil, fmt.Errorf("config path %q does not contain index %q", path, part)
			}
			value = value.Index(index)
		default:
			return nil, fmt.Errorf("config path %q cannot traverse scalar %q", path, part)
		}
	}
	return value.Interface(), nil
}

func yamlField(value reflect.Value, name string) (reflect.Value, bool) {
	for index := 0; index < value.NumField(); index++ {
		field := value.Type().Field(index)
		yamlName, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if yamlName == "" {
			yamlName = field.Name
		}
		if yamlName == name {
			return value.Field(index), true
		}
	}
	return reflect.Value{}, false
}

func isScalar(value any) bool {
	if value == nil {
		return true
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.String:
		return true
	default:
		return false
	}
}

func (r Runner) terminal() bool {
	if r.Terminal != nil {
		return r.Terminal()
	}
	return prompt.CanPrompt()
}
