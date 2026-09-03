// Package ibmcloud provides the small IBM Cloud CLI discovery seam used by ICT.
package ibmcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
)

var (
	zonePattern   = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+-[0-9]+$`)
	flavorPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]*[0-9]x[0-9]+$`)
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
	cmd.Env = environ
	output, err := cmd.Output()
	if err != nil {
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
	return d.values(ctx, `^[^\s].*$`, "resource", "groups", "--output", "json", "-q")
}

func (d Discovery) Zones(ctx context.Context) ([]string, error) {
	return d.values(ctx, zonePattern.String(), "ks", "locations", "--provider", "vpc-gen2", "--output", "json", "-q")
}

func (d Discovery) Flavors(ctx context.Context, zone string) ([]string, error) {
	return d.values(ctx, flavorPattern.String(), "ks", "flavor", "ls", "--zone", zone, "--provider", "vpc-gen2", "--output", "json", "-q")
}

func (d Discovery) Versions(ctx context.Context, platform string) ([]string, error) {
	service := "Kubernetes"
	if platform == "openshift" {
		service = "OpenShift"
	}
	return d.values(ctx, `^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:_openshift)?$`, "ks", "versions", "--show-version", service, "--output", "json", "-q")
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
