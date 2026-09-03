// Package workflow implements the guarded VPC Terraform lifecycle.
package workflow

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bevicted/ict/internal/config"
	"github.com/bevicted/ict/internal/ibmcloud"
	"github.com/bevicted/ict/internal/prompt"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

var (
	zonePattern    = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+-[0-9]+$`)
	flavorPattern  = regexp.MustCompile(`^[a-z][a-z0-9.-]*[0-9]x[0-9]+$`)
	clusterPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	versionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?:_openshift)?$`)
)

// Inputs are transient VPC plan/create options.
type Inputs struct {
	ConfigPath    string
	Target        string
	Provider      string
	Platform      string
	Version       string
	ResourceGroup string
	Zone          string
	Flavor        string
	WorkerCount   int
	Owner         string
	Name          string
}

// Values are the normalized values persisted in tfvars and recovery context.
type Values struct {
	ClusterName       string `json:"cluster_name"`
	ResourceGroupName string `json:"resource_group_name"`
	Region            string `json:"region"`
	ClusterMode       string `json:"cluster_mode"`
	Platform          string `json:"platform"`
	KubeVersion       string `json:"kube_version"`
	WorkerCount       int    `json:"worker_count"`
	Zone              string `json:"zone"`
	Flavor            string `json:"flavor"`
}

// RecoveryContext holds exactly the non-secret data needed to safely destroy the active state.
type RecoveryContext struct {
	Version   int              `json:"version"`
	Target    string           `json:"target"`
	Endpoints config.Endpoints `json:"endpoints"`
	Values    Values           `json:"values"`
}

// CommandRunner is the injectable Terraform subprocess seam.
type CommandRunner interface {
	Run(context.Context, []string, string, ...string) ([]byte, error)
}

// ExecRunner invokes executable commands from PATH.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, environ []string, command string, args ...string) ([]byte, error) {
	if command != "terraform" {
		return nil, fmt.Errorf("unsupported Terraform command %q", command)
	}
	cmd := exec.CommandContext(ctx, "terraform", args...)
	cmd.Env = environ
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("run terraform: %w", err)
	}
	return output, nil
}

// Runner wires filesystem and subprocess dependencies for a command invocation.
type Runner struct {
	Terraform CommandRunner
	IBMCloud  ibmcloud.Runner
	Workspace string
	Environ   []string
	Terminal  func() bool
	Now       func() time.Time
	Suffix    func() string
}

func (r Runner) baseEnvironment() []string {
	if r.Environ != nil {
		return r.Environ
	}
	return os.Environ()
}

func (r Runner) environment(endpoints map[string]string) []string {
	base := r.baseEnvironment()
	values := make(map[string]string, len(base)+len(endpoints))
	for _, entry := range base {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	for key, value := range endpoints {
		values[key] = value
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

func (r Runner) workspace() (string, error) {
	if r.Workspace != "" {
		return r.Workspace, nil
	}
	return ictterraform.Workspace()
}

func (r Runner) terraform() CommandRunner {
	if r.Terraform != nil {
		return r.Terraform
	}
	return ExecRunner{}
}

func (r Runner) terminal() bool {
	if r.Terminal != nil {
		return r.Terminal()
	}
	return prompt.CanPrompt()
}

// Plan initializes and runs Terraform's non-mutating plan action.
func (r Runner) Plan(ctx context.Context, supplied Inputs) error { return r.run(ctx, "plan", supplied) }

// Create initializes and applies Terraform with explicit auto-approval.
func (r Runner) Create(ctx context.Context, supplied Inputs) error {
	return r.run(ctx, "create", supplied)
}

func (r Runner) run(ctx context.Context, action string, supplied Inputs) error {
	cfg, _, err := config.LoadDiscovered(supplied.ConfigPath)
	if err != nil {
		return err
	}
	values, target, err := r.resolve(ctx, cfg, supplied)
	if err != nil {
		return err
	}
	workspace, err := r.workspace()
	if err != nil {
		return err
	}
	if err := ictterraform.Materialize(workspace); err != nil {
		return err
	}
	environment := r.environment(target.Environment())
	managed := r.hasState(ctx, environment, workspace)
	contextPath := filepath.Join(workspace, ictterraform.ContextName)
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	recovery := RecoveryContext{Version: 1, Target: target.Name, Endpoints: target.Endpoints, Values: values}
	if managed {
		if err := savedInputsMatch(tfvarsPath, contextPath, recovery); err != nil {
			return err
		}
	} else if err := writeJSON(tfvarsPath, values); err != nil {
		return err
	}

	if _, err := r.terraform().Run(ctx, environment, "terraform", "-chdir="+workspace, "init", "-input=false"); err != nil {
		return err
	}
	if action == "create" {
		if !managed {
			if err := writeJSON(contextPath, recovery); err != nil {
				return err
			}
		}
		_, err = r.terraform().Run(ctx, environment, "terraform", "-chdir="+workspace, "apply", "-input=false", "-auto-approve", "-var-file="+tfvarsPath)
		return err
	}
	if _, err := r.terraform().Run(ctx, environment, "terraform", "-chdir="+workspace, "plan", "-input=false", "-var-file="+tfvarsPath); err != nil {
		return err
	}
	if !r.hasState(ctx, environment, workspace) {
		return writeJSON(contextPath, recovery)
	}
	return nil
}

// Destroy uses only saved inputs and endpoints and refuses empty state.
func (r Runner) Destroy(ctx context.Context) error {
	workspace, err := r.workspace()
	if err != nil {
		return err
	}
	contextPath := filepath.Join(workspace, ictterraform.ContextName)
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	recovery, err := readRecovery(contextPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(tfvarsPath); err != nil {
		return fmt.Errorf("no saved Terraform values at %s; cannot safely destroy state", tfvarsPath)
	}
	if err := ictterraform.Materialize(workspace); err != nil {
		return err
	}
	environment := r.environment(config.ResolvedTarget{Target: config.Target{Endpoints: recovery.Endpoints}}.Environment())
	if !r.hasState(ctx, environment, workspace) {
		return errors.New("Terraform state has no managed resources; refusing destroy")
	}
	if _, err := r.terraform().Run(ctx, environment, "terraform", "-chdir="+workspace, "init", "-input=false"); err != nil {
		return err
	}
	_, err = r.terraform().Run(ctx, environment, "terraform", "-chdir="+workspace, "destroy", "-input=false", "-auto-approve", "-var-file="+tfvarsPath)
	return err
}

func (r Runner) hasState(ctx context.Context, environ []string, workspace string) bool {
	output, err := r.terraform().Run(ctx, environ, "terraform", "-chdir="+workspace, "state", "list")
	return err == nil && strings.TrimSpace(string(output)) != ""
}

func (r Runner) resolve(ctx context.Context, cfg *config.Config, supplied Inputs) (Values, config.ResolvedTarget, error) {
	missing := missingFields(supplied)
	if len(missing) > 0 {
		if !r.terminal() {
			return Values{}, config.ResolvedTarget{}, &prompt.MissingInputError{Fields: missing}
		}
		if _, err := exec.LookPath("fzf"); err != nil {
			return Values{}, config.ResolvedTarget{}, &prompt.MissingInputError{Fields: missing}
		}
		var err error
		supplied, err = r.discover(ctx, cfg, supplied)
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		missing = missingFields(supplied)
		if len(missing) > 0 {
			return Values{}, config.ResolvedTarget{}, &prompt.MissingInputError{Fields: missing}
		}
	}
	if supplied.Provider != string(config.ProviderVPCGen2) {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("provider %q is not supported by this VPC lifecycle", supplied.Provider)
	}
	targetProfile, err := cfg.Target(supplied.Target)
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	if !containsProvider(targetProfile.Providers, config.ProviderVPCGen2) {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("target %q does not support provider %q", supplied.Target, supplied.Provider)
	}
	if supplied.Platform != "kubernetes" && supplied.Platform != "openshift" {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid platform %q", supplied.Platform)
	}
	version, err := normalizeVersion(supplied.Platform, supplied.Version)
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	if !zonePattern.MatchString(supplied.Zone) {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid zone %q", supplied.Zone)
	}
	if !flavorPattern.MatchString(supplied.Flavor) {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid flavor %q", supplied.Flavor)
	}
	if strings.TrimSpace(supplied.ResourceGroup) == "" {
		return Values{}, config.ResolvedTarget{}, errors.New("resource group is required")
	}
	region := strings.TrimSuffix(supplied.Zone, "-"+supplied.Zone[strings.LastIndex(supplied.Zone, "-")+1:])
	target, err := cfg.ResolveTargetForRegion(supplied.Target, region, r.baseEnvironment())
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	workers := supplied.WorkerCount
	if workers == 0 {
		workers = 1
		if supplied.Platform == "openshift" {
			workers = 2
		}
	}
	if workers < 1 {
		return Values{}, config.ResolvedTarget{}, errors.New("worker count must be at least one")
	}
	name := supplied.Name
	if name == "" {
		ownerInput := supplied.Owner
		if ownerInput == "" {
			ownerInput = environmentValue(r.baseEnvironment(), "USER")
			if ownerInput == "" {
				ownerInput = "user"
			}
		}
		owner, err := normalizeOwner(ownerInput)
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		now := time.Now().UTC()
		if r.Now != nil {
			now = r.Now().UTC()
		}
		var suffix string
		if r.Suffix != nil {
			suffix = r.Suffix()
		} else {
			suffix, err = randomSuffix()
			if err != nil {
				return Values{}, config.ResolvedTarget{}, err
			}
		}
		name = generatedName(owner, now, suffix)
	}
	if !clusterPattern.MatchString(name) {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid name %q", name)
	}
	return Values{ClusterName: name, ResourceGroupName: supplied.ResourceGroup, Region: region, ClusterMode: "vpc", Platform: supplied.Platform, KubeVersion: version, WorkerCount: workers, Zone: supplied.Zone, Flavor: supplied.Flavor}, target, nil
}

func (r Runner) discover(ctx context.Context, cfg *config.Config, in Inputs) (Inputs, error) {
	choose := func(label string, values []string) (string, error) { return prompt.Select(ctx, label, values) }
	if in.Target == "" {
		names := make([]string, 0, len(cfg.Targets))
		for name := range cfg.Targets {
			names = append(names, name)
		}
		sort.Strings(names)
		value, err := choose("target", names)
		if err != nil {
			return in, err
		}
		in.Target = value
	}
	if in.Provider == "" {
		value, err := choose("provider", []string{string(config.ProviderVPCGen2)})
		if err != nil {
			return in, err
		}
		in.Provider = value
	}
	if in.Platform == "" {
		value, err := choose("platform", []string{"kubernetes", "openshift"})
		if err != nil {
			return in, err
		}
		in.Platform = value
	}
	target, err := cfg.ResolveTarget(in.Target, r.baseEnvironment())
	if err != nil {
		return in, err
	}
	d := ibmcloud.Discovery{Runner: r.IBMCloud, Environ: r.environment(target.Environment())}
	if in.ResourceGroup == "" {
		values, err := d.ResourceGroups(ctx)
		if err != nil {
			return in, err
		}
		value, err := choose("resource group", values)
		if err != nil {
			return in, err
		}
		in.ResourceGroup = value
	}
	if in.Zone == "" {
		values, err := d.Zones(ctx)
		if err != nil {
			return in, err
		}
		value, err := choose("zone", values)
		if err != nil {
			return in, err
		}
		in.Zone = value
	}
	if in.Version == "" {
		values, err := d.Versions(ctx, in.Platform)
		if err != nil {
			return in, err
		}
		value, err := choose("version", values)
		if err != nil {
			return in, err
		}
		in.Version = value
	}
	if in.Flavor == "" {
		values, err := d.Flavors(ctx, in.Zone)
		if err != nil {
			return in, err
		}
		value, err := choose("flavor", values)
		if err != nil {
			return in, err
		}
		in.Flavor = value
	}
	return in, nil
}

func missingFields(in Inputs) []string {
	fields := make([]string, 0, 7)
	for _, field := range []struct{ name, value string }{{"target", in.Target}, {"provider", in.Provider}, {"platform", in.Platform}, {"version", in.Version}, {"resource-group", in.ResourceGroup}, {"zone", in.Zone}, {"flavor", in.Flavor}} {
		if field.value == "" {
			fields = append(fields, field.name)
		}
	}
	return fields
}

func environmentValue(environ []string, wanted string) string {
	for _, entry := range environ {
		if key, value, found := strings.Cut(entry, "="); found && key == wanted {
			return value
		}
	}
	return ""
}

func containsProvider(values []config.Provider, wanted config.Provider) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func normalizeVersion(platform, value string) (string, error) {
	match := versionPattern.FindStringSubmatch(value)
	if match == nil {
		return "", fmt.Errorf("invalid %s version %q", platform, value)
	}
	if platform == "openshift" {
		return match[1] + "." + match[2] + "_openshift", nil
	}
	return match[1] + "." + match[2], nil
}
func normalizeOwner(value string) (string, error) {
	value = strings.ToLower(value)
	value = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "", errors.New("owner must contain a letter or digit")
	}
	return value, nil
}
func generatedName(owner string, now time.Time, suffix string) string {
	return fmt.Sprintf("%s-%s-%s", truncate(owner, 10), now.UTC().Format("060102150405"), suffix)
}
func randomSuffix() (string, error) {
	bytes := make([]byte, 4)
	if _, err := cryptorand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate cluster name suffix: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
func truncate(value string, length int) string {
	if len(value) > length {
		return value[:length]
	}
	return value
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return ictterraform.AtomicWrite(path, append(data, '\n'))
}
func readRecovery(path string) (RecoveryContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RecoveryContext{}, fmt.Errorf("no saved context at %s; cannot safely destroy endpoints", path)
	}
	var recovery RecoveryContext
	if err := json.Unmarshal(data, &recovery); err != nil || recovery.Version != 1 || recovery.Target == "" {
		return RecoveryContext{}, errors.New("invalid saved context")
	}
	return recovery, nil
}
func savedInputsMatch(tfvarsPath, contextPath string, expected RecoveryContext) error {
	tfvars, err := os.ReadFile(tfvarsPath)
	if err != nil {
		return errors.New("Terraform state manages resources but saved recovery inputs are missing")
	}
	var actualValues Values
	if json.Unmarshal(tfvars, &actualValues) != nil {
		return errors.New("Terraform state manages resources but saved recovery inputs are invalid")
	}
	actual, err := readRecovery(contextPath)
	if err != nil || !reflect.DeepEqual(actualValues, expected.Values) || !reflect.DeepEqual(actual, expected) {
		return errors.New("Terraform state manages resources and requested inputs differ from saved recovery inputs")
	}
	return nil
}
