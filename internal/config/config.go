// Package config loads and validates ICT target profiles.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

const Version = 1

var (
	targetNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	regionPattern     = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+$`)
)

// Provider is a cluster provider supported by a target profile.
type Provider string

const (
	ProviderVPCGen2   Provider = "vpc-gen2"
	ProviderClassic   Provider = "classic"
	ProviderSatellite Provider = "satellite"
)

// Config is the versioned, reusable target configuration.
type Config struct {
	Version int               `yaml:"version"`
	Targets map[string]Target `yaml:"targets"`
}

// Target describes one named environment and its supported providers.
type Target struct {
	Providers     []Provider `yaml:"providers"`
	DefaultRegion string     `yaml:"default_region"`
	Endpoints     Endpoints  `yaml:"endpoints"`
}

// Endpoints holds the service endpoints used by IBM Cloud CLI and Terraform.
type Endpoints struct {
	IAM                string `yaml:"iam"`
	ContainerService   string `yaml:"container_service"`
	GlobalTagging      string `yaml:"global_tagging"`
	ResourceManagement string `yaml:"resource_management"`
	ResourceController string `yaml:"resource_controller"`
	VPC                string `yaml:"vpc"`
	Satellite          string `yaml:"satellite"`
	SatelliteConfig    string `yaml:"satellite_config"`
}

// ResolvedTarget is a target after endpoint environment overrides are applied.
type ResolvedTarget struct {
	Name string
	Target
}

// DiscoverPath resolves the required config file in precedence order.
func DiscoverPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if path := os.Getenv("ICT_CONFIG"); path != "" {
		return path, nil
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "ict", "config.yaml"), nil
}

// LoadDiscovered resolves and loads the required configuration file.
func LoadDiscovered(explicit string) (*Config, string, error) {
	path, err := DiscoverPath(explicit)
	if err != nil {
		return nil, "", err
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

// Load reads a required, strict, single-document configuration file.
func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file, yaml.DisallowUnknownField())
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config %q is empty", path)
		}
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("config %q contains multiple YAML documents", path)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	return &cfg, nil
}

// Validate verifies every target profile, including profiles not selected by a command.
func (c Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if len(c.Targets) == 0 {
		return errors.New("targets must contain at least one profile")
	}
	for name, target := range c.Targets {
		if !targetNamePattern.MatchString(name) {
			return fmt.Errorf("invalid target %q", name)
		}
		if err := target.validate(name); err != nil {
			return err
		}
	}
	return nil
}

func (t Target) validate(name string) error {
	return t.validateEndpoints(name, true)
}

func (t Target) validateResolved(name string) error {
	return t.validateEndpoints(name, false)
}

func (t Target) validateEndpoints(name string, requireVPCTemplate bool) error {
	if !regionPattern.MatchString(t.DefaultRegion) {
		return fmt.Errorf("target %q has invalid default_region %q", name, t.DefaultRegion)
	}
	if len(t.Providers) == 0 {
		return fmt.Errorf("target %q must declare at least one provider", name)
	}
	providers := make(map[Provider]bool, len(t.Providers))
	for _, provider := range t.Providers {
		switch provider {
		case ProviderVPCGen2, ProviderClassic, ProviderSatellite:
			if providers[provider] {
				return fmt.Errorf("target %q declares provider %q more than once", name, provider)
			}
			providers[provider] = true
		default:
			return fmt.Errorf("target %q has unsupported provider %q", name, provider)
		}
	}
	if err := t.Endpoints.validateURLFields(name, requireVPCTemplate); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"iam", t.Endpoints.IAM},
		{"container_service", t.Endpoints.ContainerService},
		{"global_tagging", t.Endpoints.GlobalTagging},
		{"resource_management", t.Endpoints.ResourceManagement},
		{"resource_controller", t.Endpoints.ResourceController},
	} {
		if field.value == "" {
			return fmt.Errorf("target %q has incomplete endpoints: %s is required", name, field.name)
		}
	}
	if providers[ProviderVPCGen2] || providers[ProviderSatellite] {
		if t.Endpoints.VPC == "" {
			return fmt.Errorf("target %q has incomplete endpoints: vpc is required", name)
		}
	}
	if providers[ProviderSatellite] {
		for _, field := range []struct {
			name  string
			value string
		}{
			{"satellite", t.Endpoints.Satellite},
			{"satellite_config", t.Endpoints.SatelliteConfig},
		} {
			if field.value == "" {
				return fmt.Errorf("target %q has incomplete endpoints: %s is required", name, field.name)
			}
		}
	}
	return nil
}

func (e Endpoints) validateURLFields(name string, requireVPCTemplate bool) error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"iam", e.IAM},
		{"container_service", e.ContainerService},
		{"global_tagging", e.GlobalTagging},
		{"resource_management", e.ResourceManagement},
		{"resource_controller", e.ResourceController},
		{"satellite", e.Satellite},
		{"satellite_config", e.SatelliteConfig},
	} {
		if field.value != "" {
			if err := validateURL(field.value); err != nil {
				return fmt.Errorf("target %q has invalid %s endpoint: %w", name, field.name, err)
			}
		}
	}
	if e.VPC != "" {
		if !requireVPCTemplate {
			if err := validateURL(e.VPC); err != nil {
				return fmt.Errorf("target %q has invalid vpc endpoint: %w", name, err)
			}
			return nil
		}
		endpoint := strings.Replace(e.VPC, "{region}", "us-south", 1)
		if strings.Count(e.VPC, "{region}") != 1 || strings.ContainsAny(endpoint, "{}") {
			return fmt.Errorf("target %q has invalid vpc endpoint template", name)
		}
		if err := validateURL(endpoint); err != nil {
			return fmt.Errorf("target %q has invalid vpc endpoint template: %w", name, err)
		}
	}
	return nil
}

func validateURL(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

// Target looks up a target by its exact name.
func (c Config) Target(name string) (Target, error) {
	target, ok := c.Targets[name]
	if !ok {
		names := make([]string, 0, len(c.Targets))
		for targetName := range c.Targets {
			names = append(names, targetName)
		}
		sort.Strings(names)
		return Target{}, fmt.Errorf("unknown target %q (available: %s)", name, strings.Join(names, ", "))
	}
	return target, nil
}

// ResolveTarget applies endpoint variables using the profile default region.
func (c Config) ResolveTarget(name string, environ []string) (ResolvedTarget, error) {
	target, err := c.Target(name)
	if err != nil {
		return ResolvedTarget{}, err
	}
	return c.resolveTarget(name, target, target.DefaultRegion, environ)
}

// ResolveTargetForRegion applies endpoint variables after a VPC zone selects its region.
func (c Config) ResolveTargetForRegion(name, region string, environ []string) (ResolvedTarget, error) {
	target, err := c.Target(name)
	if err != nil {
		return ResolvedTarget{}, err
	}
	if !regionPattern.MatchString(region) {
		return ResolvedTarget{}, fmt.Errorf("invalid region %q", region)
	}
	return c.resolveTarget(name, target, region, environ)
}

func (c Config) resolveTarget(name string, target Target, region string, environ []string) (ResolvedTarget, error) {
	target.Endpoints.VPC = strings.ReplaceAll(target.Endpoints.VPC, "{region}", region)
	overrides := make(map[string]string, len(environ))
	for _, entry := range environ {
		key, value, found := strings.Cut(entry, "=")
		if found {
			overrides[key] = value
		}
	}
	applyOverride := func(key string, destination *string) {
		if value, ok := overrides[key]; ok && value != "" {
			*destination = value
		}
	}
	applyOverride("IBMCLOUD_IAM_API_ENDPOINT", &target.Endpoints.IAM)
	applyOverride("IBMCLOUD_CS_API_ENDPOINT", &target.Endpoints.ContainerService)
	applyOverride("IBMCLOUD_GT_API_ENDPOINT", &target.Endpoints.GlobalTagging)
	applyOverride("IBMCLOUD_RESOURCE_MANAGEMENT_API_ENDPOINT", &target.Endpoints.ResourceManagement)
	applyOverride("IBMCLOUD_RESOURCE_CONTROLLER_API_ENDPOINT", &target.Endpoints.ResourceController)
	applyOverride("IBMCLOUD_IS_NG_API_ENDPOINT", &target.Endpoints.VPC)
	applyOverride("IBMCLOUD_SATELLITE_API_ENDPOINT", &target.Endpoints.Satellite)
	applyOverride("IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT", &target.Endpoints.SatelliteConfig)
	if err := target.validateResolved(name); err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{Name: name, Target: target}, nil
}

// Environment returns standard IBM Cloud endpoint variables for a resolved target.
func (t ResolvedTarget) Environment() map[string]string {
	endpoints := map[string]string{
		"IBMCLOUD_IAM_API_ENDPOINT":                 t.Endpoints.IAM,
		"IBMCLOUD_CS_API_ENDPOINT":                  t.Endpoints.ContainerService,
		"IBMCLOUD_GT_API_ENDPOINT":                  t.Endpoints.GlobalTagging,
		"IBMCLOUD_RESOURCE_MANAGEMENT_API_ENDPOINT": t.Endpoints.ResourceManagement,
		"IBMCLOUD_RESOURCE_CONTROLLER_API_ENDPOINT": t.Endpoints.ResourceController,
		"IBMCLOUD_IS_NG_API_ENDPOINT":               t.Endpoints.VPC,
		"IBMCLOUD_SATELLITE_API_ENDPOINT":           t.Endpoints.Satellite,
		"IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT":    t.Endpoints.SatelliteConfig,
	}
	for key, value := range endpoints {
		if value == "" {
			delete(endpoints, key)
		}
	}
	return endpoints
}
