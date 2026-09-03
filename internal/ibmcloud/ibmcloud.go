// Package ibmcloud provides the small IBM Cloud CLI discovery seam used by ICT.
package ibmcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

var (
	zonePattern        = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+-[0-9]+$`)
	datacenterPattern  = regexp.MustCompile(`^[a-z]+[0-9]+$`)
	flavorPattern      = regexp.MustCompile(`^[a-z][a-z0-9.-]*[0-9]x[0-9]+$`)
	hostProfilePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*[0-9]x[0-9]+$`)
	rhelImagePattern   = regexp.MustCompile(`(?i)^.*rhel.*$`)
	managementPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// Runner executes a command with a scoped environment.
type Runner interface {
	Run(context.Context, []string, string, ...string) ([]byte, error)
}

// CommandRunner invokes executables from PATH.
type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, environ []string, command string, args ...string) ([]byte, error) {
	if command != "ibmcloud" {
		return nil, fmt.Errorf("unsupported discovery command %q", command)
	}
	cmd := exec.CommandContext(ctx, "ibmcloud", args...)
	cmd.Env = commandEnvironment(environ)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		if detail := strings.TrimSpace(string(output) + "\n" + stderr.String()); detail != "" {
			return nil, fmt.Errorf("run ibmcloud: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("run ibmcloud: %w", err)
	}
	return output, nil
}

// Discovery retrieves VPC choices from ibmcloud JSON output.
type Discovery struct {
	Runner  Runner
	Environ []string
}

func (d Discovery) ResourceGroups(ctx context.Context) ([]string, error) {
	if d.Runner == nil {
		d.Runner = CommandRunner{}
	}
	data, err := d.Runner.Run(ctx, d.Environ, "ibmcloud", "resource", "groups", "--output", "json", "-q")
	if err != nil {
		return nil, err
	}
	var groups []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, fmt.Errorf("decode ibmcloud resource groups JSON: %w", err)
	}
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		if strings.TrimSpace(group.Name) != "" {
			seen[group.Name] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}

func (d Discovery) Zones(ctx context.Context) ([]string, error) {
	return d.values(ctx, zonePattern.String(), "ks", "zones", "--provider", "vpc-gen2", "--output", "json", "-q")
}

func (d Discovery) Flavors(ctx context.Context, zone string) ([]string, error) {
	return d.values(ctx, flavorPattern.String(), "ks", "flavor", "ls", "--zone", zone, "--provider", "vpc-gen2", "--output", "json", "-q")
}

// ClassicDatacenters lists Classic locations available to the selected target.
func (d Discovery) ClassicDatacenters(ctx context.Context) ([]string, error) {
	return d.values(ctx, datacenterPattern.String(), "ks", "zones", "--provider", "classic", "--output", "json", "-q")
}

// ClassicMachineTypes lists Classic worker machine types available in a data center.
func (d Discovery) ClassicMachineTypes(ctx context.Context, datacenter string) ([]string, error) {
	return d.values(ctx, flavorPattern.String(), "ks", "flavor", "ls", "--zone", datacenter, "--provider", "classic", "--output", "json", "-q")
}

// SatelliteManagedFrom lists the public management locations exposed by Satellite.
func (d Discovery) SatelliteManagedFrom(ctx context.Context) ([]string, error) {
	if d.Runner == nil {
		d.Runner = CommandRunner{}
	}
	data, err := d.Runner.Run(ctx, d.Environ, "ibmcloud", "ks", "locations", "--output", "json", "-q")
	if err != nil {
		return nil, err
	}
	var locations []struct {
		ID               string `json:"id"`
		Kind             string `json:"kind"`
		Metro            string `json:"metro"`
		SatelliteEnabled bool   `json:"satelliteEnabled"`
	}
	if err := json.Unmarshal(data, &locations); err != nil {
		return nil, fmt.Errorf("decode ibmcloud locations JSON: %w", err)
	}
	seen := map[string]struct{}{}
	for _, location := range locations {
		if !location.SatelliteEnabled {
			continue
		}
		if location.Kind == "metro" && managementPattern.MatchString(location.ID) {
			seen[location.ID] = struct{}{}
		}
		if managementPattern.MatchString(location.Metro) {
			seen[location.Metro] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}

// SatelliteHostImages lists public RHEL images suitable for Satellite hosts.
func (d Discovery) SatelliteHostImages(ctx context.Context) ([]string, error) {
	return d.values(ctx, rhelImagePattern.String(), "is", "images", "--visibility", "public", "--output", "json")
}

// SatelliteHostProfiles lists VPC instance profiles suitable for Satellite hosts.
func (d Discovery) SatelliteHostProfiles(ctx context.Context) ([]string, error) {
	return d.values(ctx, hostProfilePattern.String(), "is", "instance-profiles", "--output", "json")
}

func (d Discovery) Versions(ctx context.Context, platform string) ([]string, error) {
	service := "Kubernetes"
	responseKey := "kubernetes"
	suffix := ""
	if platform == "openshift" {
		service = "OpenShift"
		responseKey = "openshift"
		suffix = "_openshift"
	}
	if d.Runner == nil {
		d.Runner = CommandRunner{}
	}
	data, err := d.Runner.Run(ctx, d.Environ, "ibmcloud", "ks", "versions", "--show-version", service, "--output", "json", "-q")
	if err != nil {
		return nil, err
	}
	var response map[string][]struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
		Patch int `json:"patch"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode ibmcloud versions JSON: %w", err)
	}
	versions := response[responseKey]
	values := make([]string, 0, len(versions))
	for _, version := range versions {
		values = append(values, fmt.Sprintf("%d.%d.%d%s", version.Major, version.Minor, version.Patch, suffix))
	}
	return values, nil
}

func (d Discovery) values(ctx context.Context, expression string, args ...string) ([]string, error) {
	if d.Runner == nil {
		d.Runner = CommandRunner{}
	}
	data, err := d.Runner.Run(ctx, d.Environ, "ibmcloud", args...)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode ibmcloud JSON: %w", err)
	}
	pattern := regexp.MustCompile(expression)
	seen := map[string]struct{}{}
	collectStrings(decoded, func(value string) {
		if pattern.MatchString(value) {
			seen[value] = struct{}{}
		}
	})
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}

func commandEnvironment(environ []string) []string {
	values := make(map[string]string, len(environ)+1)
	for _, entry := range environ {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	if endpoint := values["IBMCLOUD_CS_API_ENDPOINT"]; endpoint != "" {
		endpoint = strings.TrimRight(endpoint, "/")
		values["IKS_API_CS_ENDPOINT"] = strings.TrimSuffix(endpoint, "/global")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func collectStrings(value any, visit func(string)) {
	switch typed := value.(type) {
	case string:
		visit(typed)
	case []any:
		for _, item := range typed {
			collectStrings(item, visit)
		}
	case map[string]any:
		for key, item := range typed {
			if key == "name" || key == "version" || key == "id" {
				if text, ok := item.(string); ok {
					visit(text)
				}
			}
			collectStrings(item, visit)
		}
	}
}
