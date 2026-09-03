package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/bevicted/ict/internal/prompt"
	"github.com/goccy/go-yaml"
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

func (r Runner) stdout() io.Writer {
	if r.Stdout != nil {
		return r.Stdout
	}
	return os.Stdout
}

func valueAt(cfg *Config, path string) (any, error) {
	if path == "" {
		return nil, fmt.Errorf("invalid config path %q", path)
	}
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid config path %q", path)
		}
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
			if err != nil || index < 0 || index >= value.Len() {
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
		yamlName := strings.Split(field.Tag.Get("yaml"), ",")[0]
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
