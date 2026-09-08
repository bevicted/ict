// Package workflow implements the guarded VPC Terraform lifecycle.
package workflow

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bevicted/ict/internal/config"
	"github.com/bevicted/ict/internal/ibmcloud"
	"github.com/bevicted/ict/internal/prompt"
	ictterraform "github.com/bevicted/ict/internal/terraform"
)

var (
	zonePattern             = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+-[0-9]+$`)
	datacenterPattern       = regexp.MustCompile(`^[a-z]+[0-9]+$`)
	flavorPattern           = regexp.MustCompile(`^[a-z][a-z0-9.-]*[0-9]x[0-9]+$`)
	vpcClusterPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	classicClusterPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,34}$`)
	satelliteClusterPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,43}$`)
	hostProfilePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]*[0-9]x[0-9]+$`)
	vlanPattern             = regexp.MustCompile(`^[0-9]+$`)
	versionPattern          = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?:_openshift)?$`)

	errSatelliteSSHPublicKeyRequired = errors.New("Satellite SSH public key is required")
	errInvalidSatelliteSSHPublicKey  = errors.New("invalid Satellite SSH public key")
	errSatelliteSSHPublicKeyEmpty    = errors.New("Satellite SSH public key is empty")
	errIncompleteRecoveryContext     = errors.New("incomplete or invalid saved context; cannot safely destroy")
)

// Inputs are transient create options.
type Inputs struct {
	ConfigPath                     string
	Target                         string
	Provider                       string
	Platform                       string
	Version                        string
	ResourceGroup                  string
	Zone                           string
	Flavor                         string
	VPCID                          string
	SubnetIDs                      []string
	PublicGatewayIDs               []string
	Datacenter                     string
	MachineType                    string
	PublicVLANID                   string
	PrivateVLANID                  string
	SatelliteZones                 []string
	SatelliteManagedFrom           string
	SatelliteLocationID            string
	SatelliteHostImage             string
	SatelliteHostProfile           string
	SatelliteSSHPublicKeyPath      string
	SatelliteSSHKeyID              string
	SatelliteWorkerInstanceIDs     []string
	SatelliteWorkerOperatingSystem string
	WorkerCount                    int
	Owner                          string
	Prefix                         string
	Name                           string
}

// Values are the normalized values persisted in tfvars and recovery context.
type Values struct {
	ClusterName                    string   `json:"cluster_name"`
	ResourceGroupName              string   `json:"resource_group_name"`
	Region                         string   `json:"region"`
	ClusterMode                    string   `json:"cluster_mode"`
	Platform                       string   `json:"platform"`
	KubeVersion                    string   `json:"kube_version"`
	WorkerCount                    int      `json:"worker_count"`
	Zone                           string   `json:"zone,omitempty"`
	Flavor                         string   `json:"flavor,omitempty"`
	VPCID                          string   `json:"vpc_id,omitempty"`
	SubnetIDs                      []string `json:"subnet_ids,omitempty"`
	PublicGatewayIDs               []string `json:"public_gateway_ids,omitempty"`
	Datacenter                     string   `json:"datacenter,omitempty"`
	MachineType                    string   `json:"machine_type,omitempty"`
	PublicVLANID                   string   `json:"public_vlan_id,omitempty"`
	PrivateVLANID                  string   `json:"private_vlan_id,omitempty"`
	SatelliteZones                 []string `json:"satellite_zones,omitempty"`
	SatelliteManagedFrom           string   `json:"satellite_managed_from,omitempty"`
	SatelliteLocationID            string   `json:"satellite_location_id,omitempty"`
	SatelliteHostImage             string   `json:"satellite_host_image,omitempty"`
	SatelliteHostProfile           string   `json:"satellite_host_profile,omitempty"`
	SatelliteSSHPublicKey          string   `json:"satellite_ssh_public_key,omitempty"`
	SatelliteSSHKeyID              string   `json:"satellite_ssh_key_id,omitempty"`
	SatelliteWorkerInstanceIDs     []string `json:"satellite_worker_instance_ids,omitempty"`
	SatelliteWorkerOperatingSystem string   `json:"satellite_worker_operating_system,omitempty"`
}

// RecoveryContext holds exactly the non-secret data needed to safely destroy the active state.
type RecoveryContext struct {
	Version                          int              `json:"version"`
	Target                           string           `json:"target"`
	Endpoints                        config.Endpoints `json:"endpoints"`
	Values                           Values           `json:"values"`
	SatelliteSSHPublicKeyFingerprint string           `json:"satellite_ssh_public_key_fingerprint,omitempty"`
	TFVarsSHA256                     string           `json:"tfvars_sha256"`
}

// PlanResult is the strict non-secret handoff from a disposable planning workspace.
type PlanResult struct {
	Version  int                        `json:"version"`
	StateID  string                     `json:"state_id"`
	Values   Values                     `json:"values"`
	Recovery RecoveryContext            `json:"recovery"`
	Backend  ictterraform.BackendConfig `json:"backend"`
	PlanPath string                     `json:"plan_path"`
}

// OperationResult is the bounded local handoff for a completed apply or destroy.
type OperationResult struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Workspace string `json:"workspace,omitempty"`
}

// CommandRunner is the injectable Terraform subprocess seam.
type CommandRunner interface {
	Run(context.Context, []string, io.Writer, io.Writer, string, ...string) error
	Output(context.Context, []string, string, ...string) ([]byte, error)
}

// ExecRunner invokes executable commands from PATH.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, environ []string, stdout, stderr io.Writer, command string, args ...string) error {
	cmd, err := terraformCommand(ctx, environ, command, args...)
	if err != nil {
		return err
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run terraform: %w", err)
	}
	return nil
}

func (ExecRunner) Output(ctx context.Context, environ []string, command string, args ...string) ([]byte, error) {
	cmd, err := terraformCommand(ctx, environ, command, args...)
	if err != nil {
		return nil, err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if detail := strings.TrimSpace(string(output)); detail != "" {
			return output, fmt.Errorf("run terraform: %w: %s", err, detail)
		}
		return output, fmt.Errorf("run terraform: %w", err)
	}
	return output, nil
}

func terraformCommand(ctx context.Context, environ []string, command string, args ...string) (*exec.Cmd, error) {
	if command != "terraform" {
		return nil, fmt.Errorf("unsupported Terraform command %q", command)
	}
	cmd := exec.CommandContext(ctx, "terraform", args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.Env = environ
	return cmd, nil
}

// Runner wires filesystem and subprocess dependencies for a command invocation.
type Runner struct {
	Terraform   CommandRunner
	IBMCloud    ibmcloud.Runner
	Workspace   string
	Environ     []string
	Stdout      io.Writer
	Stderr      io.Writer
	Terminal    func() bool
	Now         func() time.Time
	Suffix      func() string
	Materialize func(workspace string) error
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

func (r Runner) operationWorkspace() (string, error) {
	if r.Workspace != "" {
		if err := os.MkdirAll(filepath.Dir(r.Workspace), 0o700); err != nil {
			return "", fmt.Errorf("create temporary Terraform workspace parent: %w", err)
		}
		if err := os.Mkdir(r.Workspace, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return "", fmt.Errorf("temporary Terraform workspace already exists: %s", r.Workspace)
			}
			return "", fmt.Errorf("create temporary Terraform workspace: %w", err)
		}
		return r.Workspace, nil
	}
	workspace, err := os.MkdirTemp("", "ict-operation-")
	if err != nil {
		return "", fmt.Errorf("create temporary Terraform workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		return "", fmt.Errorf("protect temporary Terraform workspace: %w", err)
	}
	return workspace, nil
}

func (r Runner) materialize(workspace string) error {
	if r.Materialize != nil {
		return r.Materialize(workspace)
	}
	return ictterraform.Materialize(workspace)
}

func (r Runner) terraform() CommandRunner {
	if r.Terraform != nil {
		return r.Terraform
	}
	return ExecRunner{}
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

func (r Runner) terminal() bool {
	if r.Terminal != nil {
		return r.Terminal()
	}
	return prompt.CanPrompt()
}

// Plan resolves inputs once, initializes the configured remote backend, and writes frozen metadata.
func (r Runner) Plan(ctx context.Context, stateID string, supplied Inputs, backend ictterraform.BackendConfig, resultPath string) error {
	if err := backend.Validate(); err != nil {
		return err
	}
	if err := ictterraform.ValidateResultPath(resultPath); err != nil {
		return err
	}
	cfg, _, err := config.LoadDiscovered(supplied.ConfigPath)
	if err != nil {
		return err
	}
	values, target, err := r.resolve(ctx, cfg, supplied)
	if err != nil {
		return err
	}
	if values.ClusterMode == "classic" {
		if err := requireClassicCredentials(r.baseEnvironment()); err != nil {
			return err
		}
	}
	recovery, err := newRecoveryContext(target, values)
	if err != nil {
		return err
	}
	tfvarsData, err := marshalJSON(values)
	if err != nil {
		return err
	}
	workspace, err := r.operationWorkspace()
	if err != nil {
		return err
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvarsData); err != nil {
		return fmt.Errorf("write runtime values: %w", err)
	}
	if err := writeJSON(filepath.Join(workspace, ictterraform.ContextName), recovery); err != nil {
		return err
	}
	if err := r.materialize(workspace); err != nil {
		return err
	}
	if err := ictterraform.MaterializeBackend(workspace); err != nil {
		return fmt.Errorf("materialize Terraform backend: %w", err)
	}
	environment := r.environment(target.Environment())
	initArgs := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, backend.InitArgs()...)
	if err := r.terraform().Run(ctx, environment, r.stdout(), r.stderr(), "terraform", initArgs...); err != nil {
		return err
	}
	planPath := filepath.Join(workspace, ictterraform.PlanName)
	if err := r.terraform().Run(ctx, environment, r.stdout(), r.stderr(), "terraform", "-chdir="+workspace, "plan", "-input=false", "-no-color", "-out="+ictterraform.PlanName, "-var-file="+tfvarsPath); err != nil {
		return err
	}
	if err := os.Chmod(planPath, 0o600); err != nil {
		return fmt.Errorf("protect saved Terraform plan: %w", err)
	}
	if err := writeJSON(resultPath, PlanResult{Version: 1, StateID: stateID, Values: values, Recovery: recovery, Backend: backend, PlanPath: planPath}); err != nil {
		return fmt.Errorf("write plan result: %w", err)
	}
	return nil
}

// Apply reconstructs frozen inputs in fresh storage and performs a fresh auto-approved apply.
func (r Runner) Apply(ctx context.Context, stateID, contextPath string, backend ictterraform.BackendConfig, resultPath string) error {
	result, err := r.loadOperationContext(stateID, contextPath, backend, resultPath)
	if err != nil {
		return err
	}
	return r.runOperation(ctx, "apply", result, resultPath)
}

// Destroy reconstructs frozen inputs in fresh storage and always asks the remote backend to destroy.
func (r Runner) Destroy(ctx context.Context, stateID, contextPath string, backend ictterraform.BackendConfig, resultPath string) error {
	result, err := r.loadOperationContext(stateID, contextPath, backend, resultPath)
	if err != nil {
		return err
	}
	return r.runOperation(ctx, "destroy", result, resultPath)
}

func (r Runner) loadOperationContext(stateID, contextPath string, backend ictterraform.BackendConfig, resultPath string) (PlanResult, error) {
	if err := backend.Validate(); err != nil {
		return PlanResult{}, err
	}
	if err := ictterraform.ValidateResultPath(resultPath); err != nil {
		return PlanResult{}, err
	}
	result, err := ReadPlanResult(contextPath)
	if err != nil {
		return PlanResult{}, err
	}
	if result.StateID != stateID {
		return PlanResult{}, errors.New("frozen context does not match lifecycle operation identifier")
	}
	if !reflect.DeepEqual(result.Backend, backend) {
		return PlanResult{}, errors.New("frozen context backend does not match backend configuration")
	}
	return result, nil
}

func (r Runner) runOperation(ctx context.Context, operation string, result PlanResult, resultPath string) error {
	workspace, err := r.operationWorkspace()
	if err != nil {
		return err
	}
	tfvarsData, err := marshalJSON(result.Values)
	if err != nil {
		return err
	}
	tfvarsPath := filepath.Join(workspace, ictterraform.TFVarsName)
	if err := ictterraform.AtomicWrite(tfvarsPath, tfvarsData); err != nil {
		return fmt.Errorf("write runtime values: %w", err)
	}
	if err := r.materialize(workspace); err != nil {
		return err
	}
	if err := ictterraform.MaterializeBackend(workspace); err != nil {
		return fmt.Errorf("materialize Terraform backend: %w", err)
	}
	environment := r.environment(config.ResolvedTarget{Target: config.Target{Endpoints: result.Recovery.Endpoints}}.Environment())
	if result.Values.ClusterMode == "classic" {
		if err := requireClassicCredentials(r.baseEnvironment()); err != nil {
			return err
		}
	}
	initArgs := append([]string{"-chdir=" + workspace, "init", "-input=false", "-no-color"}, result.Backend.InitArgs()...)
	if err := r.terraform().Run(ctx, environment, r.stdout(), r.stderr(), "terraform", initArgs...); err != nil {
		return err
	}
	args := []string{"-chdir=" + workspace, operation, "-input=false", "-no-color", "-auto-approve", "-var-file=" + tfvarsPath}
	if err := r.terraform().Run(ctx, environment, r.stdout(), r.stderr(), "terraform", args...); err != nil {
		return err
	}
	if err := writeOperationResult(resultPath, operation, workspace); err != nil {
		return err
	}
	return nil
}

func writeOperationResult(path, operation, workspace string) error {
	result := OperationResult{Version: 1, Operation: operation, Workspace: workspace}
	data, err := marshalJSON(result)
	if err != nil {
		return err
	}
	if len(data) > 4096 {
		return errors.New("operation result exceeds 4096 bytes")
	}
	if err := ictterraform.AtomicWrite(path, data); err != nil {
		return fmt.Errorf("write operation result: %w", err)
	}
	return nil
}

func (r Runner) resolve(ctx context.Context, cfg *config.Config, supplied Inputs) (Values, config.ResolvedTarget, error) {
	var err error
	if missing := selectionMissingFields(supplied); len(missing) > 0 {
		if err := r.requirePrompt(missing); err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		supplied, err = r.selectTargetAndProvider(ctx, cfg, supplied)
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
	}
	targetProfile, err := cfg.Target(supplied.Target)
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	provider := config.Provider(supplied.Provider)
	if !containsProvider(targetProfile.Providers, provider) {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("target %q does not support provider %q", supplied.Target, supplied.Provider)
	}
	if provider != config.ProviderVPCGen2 && provider != config.ProviderClassic && provider != config.ProviderSatellite {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("provider %q is not supported by this lifecycle", supplied.Provider)
	}
	if err := normalizeVPCReuseInputs(&supplied, provider); err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	if err := normalizeSatelliteReuseInputs(&supplied, provider); err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	if provider == config.ProviderSatellite && supplied.Platform != "" && supplied.Platform != "openshift" {
		return Values{}, config.ResolvedTarget{}, errors.New("Satellite requires the openshift platform")
	}
	if missing := missingFields(supplied); len(missing) > 0 {
		if err := r.requirePrompt(missing); err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		supplied, err = r.discover(ctx, cfg, supplied)
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		if missing := missingFields(supplied); len(missing) > 0 {
			return Values{}, config.ResolvedTarget{}, &prompt.MissingInputError{Fields: missing}
		}
	}
	if provider == config.ProviderSatellite {
		satelliteDefaults(&supplied)
	}
	if supplied.Platform != "kubernetes" && supplied.Platform != "openshift" {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid platform %q", supplied.Platform)
	}
	version, err := normalizeVersion(supplied.Platform, supplied.Version)
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	if strings.TrimSpace(supplied.ResourceGroup) == "" {
		return Values{}, config.ResolvedTarget{}, errors.New("resource group is required")
	}
	minimumWorkers := 1
	if supplied.Platform == "openshift" && provider != config.ProviderSatellite {
		minimumWorkers = 2
	}
	workers := supplied.WorkerCount
	if workers == 0 {
		workers = minimumWorkers
	}
	if workers < minimumWorkers {
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("worker count must be at least %d for %s", minimumWorkers, supplied.Platform)
	}
	nameLimit, err := clusterNameLimit(provider)
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}
	name, err := r.resolveName(supplied, nameLimit)
	if err != nil {
		return Values{}, config.ResolvedTarget{}, err
	}

	switch provider {
	case config.ProviderVPCGen2:
		if !zonePattern.MatchString(supplied.Zone) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid zone %q", supplied.Zone)
		}
		if !flavorPattern.MatchString(supplied.Flavor) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid flavor %q", supplied.Flavor)
		}
		if !vpcClusterPattern.MatchString(name) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid name %q", name)
		}
		region := zoneRegion(supplied.Zone)
		target, err := cfg.ResolveTargetForRegion(supplied.Target, region, r.baseEnvironment())
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		return Values{ClusterName: name, ResourceGroupName: supplied.ResourceGroup, Region: region, ClusterMode: "vpc", Platform: supplied.Platform, KubeVersion: version, WorkerCount: workers, Zone: supplied.Zone, Flavor: supplied.Flavor, VPCID: supplied.VPCID, SubnetIDs: slices.Clone(supplied.SubnetIDs), PublicGatewayIDs: slices.Clone(supplied.PublicGatewayIDs)}, target, nil
	case config.ProviderClassic:
		if !datacenterPattern.MatchString(supplied.Datacenter) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid datacenter %q", supplied.Datacenter)
		}
		if !flavorPattern.MatchString(supplied.MachineType) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid machine type %q", supplied.MachineType)
		}
		if !vlanPattern.MatchString(supplied.PublicVLANID) {
			return Values{}, config.ResolvedTarget{}, errors.New("public VLAN ID must be a numeric Classic VLAN ID")
		}
		if !vlanPattern.MatchString(supplied.PrivateVLANID) {
			return Values{}, config.ResolvedTarget{}, errors.New("private VLAN ID must be a numeric Classic VLAN ID")
		}
		if !classicClusterPattern.MatchString(name) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid name %q", name)
		}
		target, err := cfg.ResolveTarget(supplied.Target, r.baseEnvironment())
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		return Values{ClusterName: name, ResourceGroupName: supplied.ResourceGroup, Region: target.DefaultRegion, ClusterMode: "classic", Platform: supplied.Platform, KubeVersion: version, WorkerCount: workers, Datacenter: supplied.Datacenter, MachineType: supplied.MachineType, PublicVLANID: supplied.PublicVLANID, PrivateVLANID: supplied.PrivateVLANID}, target, nil
	case config.ProviderSatellite:
		if workers != 1 && workers != 3 {
			return Values{}, config.ResolvedTarget{}, errors.New("Satellite worker count must be one or three")
		}
		if !satelliteClusterPattern.MatchString(name) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid Satellite name %q", name)
		}
		region, err := satelliteRegion(supplied.SatelliteZones)
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		if len(supplied.SatelliteWorkerInstanceIDs) > 0 && len(supplied.SatelliteWorkerInstanceIDs) != workers {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("Satellite requires exactly %d satellite-worker-instance-id values", workers)
		}
		if len(supplied.SatelliteWorkerInstanceIDs) == 0 && !hostProfilePattern.MatchString(supplied.SatelliteHostProfile) {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid Satellite host profile %q", supplied.SatelliteHostProfile)
		}
		if supplied.SatelliteWorkerOperatingSystem != "RHCOS" && supplied.SatelliteWorkerOperatingSystem != "REDHAT_8_64" {
			return Values{}, config.ResolvedTarget{}, fmt.Errorf("invalid Satellite worker operating system %q", supplied.SatelliteWorkerOperatingSystem)
		}
		key := ""
		if len(supplied.SatelliteWorkerInstanceIDs) == 0 && supplied.SatelliteSSHKeyID == "" {
			key, err = readSSHPublicKey(supplied.SatelliteSSHPublicKeyPath)
			if err != nil {
				return Values{}, config.ResolvedTarget{}, err
			}
		}
		target, err := cfg.ResolveTargetForRegion(supplied.Target, region, r.baseEnvironment())
		if err != nil {
			return Values{}, config.ResolvedTarget{}, err
		}
		return Values{ClusterName: name, ResourceGroupName: supplied.ResourceGroup, Region: region, ClusterMode: "satellite", Platform: "openshift", KubeVersion: version, WorkerCount: workers, VPCID: supplied.VPCID, SubnetIDs: slices.Clone(supplied.SubnetIDs), PublicGatewayIDs: slices.Clone(supplied.PublicGatewayIDs), SatelliteZones: slices.Clone(supplied.SatelliteZones), SatelliteManagedFrom: supplied.SatelliteManagedFrom, SatelliteLocationID: supplied.SatelliteLocationID, SatelliteHostImage: supplied.SatelliteHostImage, SatelliteHostProfile: supplied.SatelliteHostProfile, SatelliteSSHPublicKey: key, SatelliteSSHKeyID: supplied.SatelliteSSHKeyID, SatelliteWorkerInstanceIDs: slices.Clone(supplied.SatelliteWorkerInstanceIDs), SatelliteWorkerOperatingSystem: supplied.SatelliteWorkerOperatingSystem}, target, nil
	default:
		return Values{}, config.ResolvedTarget{}, fmt.Errorf("provider %q is not supported by this lifecycle", supplied.Provider)
	}
}

func satelliteDefaults(in *Inputs) {
	if len(in.SatelliteWorkerInstanceIDs) == 0 && in.SatelliteHostProfile == "" {
		in.SatelliteHostProfile = "bx2-4x16"
	}
	if in.SatelliteWorkerOperatingSystem == "" {
		in.SatelliteWorkerOperatingSystem = "RHCOS"
	}
}

func zoneRegion(zone string) string {
	return zone[:strings.LastIndex(zone, "-")]
}

func satelliteRegion(zones []string) (string, error) {
	if len(zones) != 3 {
		return "", errors.New("Satellite requires exactly three VPC zones")
	}
	region := ""
	seen := make(map[string]struct{}, len(zones))
	for _, zone := range zones {
		if !zonePattern.MatchString(zone) {
			return "", fmt.Errorf("invalid Satellite zone %q", zone)
		}
		if _, duplicate := seen[zone]; duplicate {
			return "", errors.New("Satellite zones must be distinct")
		}
		seen[zone] = struct{}{}
		zoneRegion := zoneRegion(zone)
		if region == "" {
			region = zoneRegion
		} else if region != zoneRegion {
			return "", errors.New("Satellite zones must belong to one region")
		}
	}
	return region, nil
}

func regionsFromZones(zones []string) []string {
	regions := make(map[string]struct{})
	for _, zone := range zones {
		if zonePattern.MatchString(zone) {
			regions[zoneRegion(zone)] = struct{}{}
		}
	}
	values := make([]string, 0, len(regions))
	for region := range regions {
		values = append(values, region)
	}
	sort.Strings(values)
	return values
}

func zonesInRegion(zones []string, region string) []string {
	values := make([]string, 0, len(zones))
	for _, zone := range zones {
		if zoneRegion(zone) == region {
			values = append(values, zone)
		}
	}
	sort.Strings(values)
	return values
}

func publicKeyPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("find SSH public keys: %w", err)
	}
	entries, err := os.ReadDir(filepath.Join(home, ".ssh"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find SSH public keys: %w", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pub") {
			paths = append(paths, filepath.Join(home, ".ssh", entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

type sshPublicKeyReadError struct {
	cause error
}

func (e sshPublicKeyReadError) Error() string { return "read Satellite SSH public key" }
func (e sshPublicKeyReadError) Unwrap() error { return e.cause }

func readSSHPublicKey(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errSatelliteSSHPublicKeyRequired
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", sshPublicKeyReadError{cause: err}
	}
	key, err := parseSSHPublicKey(string(contents))
	if err != nil {
		return "", err
	}
	return key, nil
}

func parseSSHPublicKey(contents string) (string, error) {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !supportedSSHPublicKeyType(fields[0]) {
			return "", errInvalidSatelliteSSHPublicKey
		}
		encoded, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(encoded) < 4 {
			return "", errInvalidSatelliteSSHPublicKey
		}
		length := int(binary.BigEndian.Uint32(encoded[:4]))
		if length >= len(encoded)-4 || string(encoded[4:4+length]) != fields[0] {
			return "", errInvalidSatelliteSSHPublicKey
		}
		normalized := strings.Join(fields, " ")
		return normalized, nil
	}
	return "", errSatelliteSSHPublicKeyEmpty
}

func supportedSSHPublicKeyType(value string) bool {
	switch value {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	default:
		return false
	}
}

func sshPublicKeyFingerprint(key string) string {
	fields := strings.Fields(key)
	if len(fields) < 2 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(decoded)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func newRecoveryContext(target config.ResolvedTarget, values Values) (RecoveryContext, error) {
	data, err := marshalJSON(values)
	if err != nil {
		return RecoveryContext{}, err
	}
	fingerprint := sshPublicKeyFingerprint(values.SatelliteSSHPublicKey)
	values.SatelliteSSHPublicKey = ""
	return RecoveryContext{
		Version:                          1,
		Target:                           target.Name,
		Endpoints:                        target.Endpoints,
		Values:                           values,
		SatelliteSSHPublicKeyFingerprint: fingerprint,
		TFVarsSHA256:                     tfvarsSHA256(data),
	}, nil
}

func (r Runner) resolveName(supplied Inputs, limit int) (string, error) {
	if supplied.Prefix != "" {
		prefix, err := normalizePrefix(supplied.Prefix)
		if err != nil {
			return "", err
		}
		if supplied.Name != "" {
			name, err := normalizeName(supplied.Name)
			if err != nil {
				return "", err
			}
			return prefixedName(prefix, name, limit)
		}
		if len(prefix)+generatedNameSuffixLength > limit {
			return "", fmt.Errorf("prefix %q leaves no room for a generated name", prefix)
		}
		now := time.Now().UTC()
		if r.Now != nil {
			now = r.Now().UTC()
		}
		if r.Suffix != nil {
			return generatedPrefixedName(prefix, now, r.Suffix()), nil
		}
		suffix, err := randomSuffix()
		if err != nil {
			return "", err
		}
		return generatedPrefixedName(prefix, now, suffix), nil
	}
	if supplied.Name != "" {
		return supplied.Name, nil
	}
	ownerInput := supplied.Owner
	if ownerInput == "" {
		ownerInput = environmentValue(r.baseEnvironment(), "USER")
		if ownerInput == "" {
			ownerInput = "user"
		}
	}
	owner, err := normalizeOwner(ownerInput)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if r.Suffix != nil {
		return generatedName(owner, now, r.Suffix()), nil
	}
	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	return generatedName(owner, now, suffix), nil
}

const generatedNameSuffixLength = len("-060102150405-01234567")

func clusterNameLimit(provider config.Provider) (int, error) {
	switch provider {
	case config.ProviderVPCGen2:
		return 32, nil
	case config.ProviderClassic:
		return 35, nil
	case config.ProviderSatellite:
		return 44, nil
	default:
		return 0, fmt.Errorf("provider %q is not supported by this lifecycle", provider)
	}
}

func normalizePrefix(value string) (string, error) {
	prefix, err := normalizeOwner(value)
	if err != nil {
		return "", fmt.Errorf("invalid prefix: %w", err)
	}
	if prefix[0] >= '0' && prefix[0] <= '9' {
		return "", fmt.Errorf("prefix %q must begin with a letter", value)
	}
	return prefix, nil
}

func normalizeName(value string) (string, error) {
	name, err := normalizeOwner(value)
	if err != nil {
		return "", fmt.Errorf("invalid name: %w", err)
	}
	return name, nil
}

func prefixedName(prefix, name string, limit int) (string, error) {
	available := limit - len(prefix) - 1
	if available < 1 {
		return "", fmt.Errorf("prefix %q leaves no room for an explicit name", prefix)
	}
	return prefix + "-" + truncate(name, available), nil
}

func (r Runner) requirePrompt(fields []string) error {
	if !r.terminal() {
		return &prompt.MissingInputError{Fields: fields}
	}
	if _, err := exec.LookPath("fzf"); err != nil {
		return &prompt.MissingInputError{Fields: fields}
	}
	return nil
}

func (r Runner) selectTargetAndProvider(ctx context.Context, cfg *config.Config, in Inputs) (Inputs, error) {
	choose := func(label string, values []string) (string, error) { return prompt.Select(ctx, label, values) }
	if in.Target == "" {
		names := make([]string, 0, len(cfg.Targets))
		for name, target := range cfg.Targets {
			if in.Provider == "" || containsProvider(target.Providers, config.Provider(in.Provider)) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		value, err := choose("target", names)
		if err != nil {
			return in, err
		}
		in.Target = value
	}
	if in.Provider == "" {
		target, err := cfg.Target(in.Target)
		if err != nil {
			return in, err
		}
		providers := make([]string, 0, len(target.Providers))
		for _, provider := range target.Providers {
			providers = append(providers, string(provider))
		}
		sort.Strings(providers)
		value, err := choose("provider", providers)
		if err != nil {
			return in, err
		}
		in.Provider = value
	}
	return in, nil
}

func (r Runner) discover(ctx context.Context, cfg *config.Config, in Inputs) (Inputs, error) {
	choose := func(label string, values []string) (string, error) { return prompt.Select(ctx, label, values) }
	if in.Platform == "" {
		platforms := []string{"kubernetes", "openshift"}
		if config.Provider(in.Provider) == config.ProviderSatellite {
			platforms = []string{"openshift"}
		}
		value, err := choose("platform", platforms)
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
		value, err := prompt.SelectWithLoader(ctx, "resource group", d.ResourceGroups)
		if err != nil {
			return in, err
		}
		in.ResourceGroup = value
	}
	if in.Version == "" {
		value, err := prompt.SelectWithLoader(ctx, "version", func(ctx context.Context) ([]string, error) {
			return d.Versions(ctx, in.Platform)
		})
		if err != nil {
			return in, err
		}
		in.Version = value
	}
	switch config.Provider(in.Provider) {
	case config.ProviderVPCGen2:
		if in.Zone == "" {
			value, err := prompt.SelectWithLoader(ctx, "zone", d.Zones)
			if err != nil {
				return in, err
			}
			in.Zone = value
		}
		if in.Flavor == "" {
			value, err := prompt.SelectWithLoader(ctx, "flavor", func(ctx context.Context) ([]string, error) {
				return d.Flavors(ctx, in.Zone)
			})
			if err != nil {
				return in, err
			}
			in.Flavor = value
		}
	case config.ProviderClassic:
		if in.Datacenter == "" {
			value, err := prompt.SelectWithLoader(ctx, "datacenter", d.ClassicDatacenters)
			if err != nil {
				return in, err
			}
			in.Datacenter = value
		}
		if in.MachineType == "" {
			value, err := prompt.SelectWithLoader(ctx, "machine type", func(ctx context.Context) ([]string, error) {
				return d.ClassicMachineTypes(ctx, in.Datacenter)
			})
			if err != nil {
				return in, err
			}
			in.MachineType = value
		}
	case config.ProviderSatellite:
		if in.SatelliteLocationID == "" && in.SatelliteManagedFrom == "" {
			value, err := prompt.SelectWithLoader(ctx, "Satellite management location", d.SatelliteManagedFrom)
			if err != nil {
				return in, err
			}
			in.SatelliteManagedFrom = value
		}
		if len(in.SatelliteZones) != 3 {
			var zones []string
			region, err := prompt.SelectWithLoader(ctx, "Satellite region", func(ctx context.Context) ([]string, error) {
				var err error
				zones, err = d.Zones(ctx)
				return regionsFromZones(zones), err
			})
			if err != nil {
				return in, err
			}
			zones = zonesInRegion(zones, region)
			in.SatelliteZones, err = prompt.SelectMany(ctx, "Satellite zones", zones)
			if err != nil {
				return in, err
			}
			regional, err := cfg.ResolveTargetForRegion(in.Target, region, r.baseEnvironment())
			if err != nil {
				return in, err
			}
			d.Environ = r.environment(regional.Environment())
		}
		if len(in.SatelliteWorkerInstanceIDs) == 0 && in.SatelliteHostProfile == "" {
			value, err := prompt.SelectWithLoader(ctx, "Satellite host profile", d.SatelliteHostProfiles)
			if err != nil {
				return in, err
			}
			in.SatelliteHostProfile = value
		}
		if in.SatelliteWorkerOperatingSystem == "" {
			value, err := choose("Satellite worker operating system", []string{"RHCOS", "REDHAT_8_64"})
			if err != nil {
				return in, err
			}
			in.SatelliteWorkerOperatingSystem = value
		}
		if len(in.SatelliteWorkerInstanceIDs) == 0 && in.SatelliteHostImage == "" {
			value, err := prompt.SelectWithLoader(ctx, "Satellite host image", d.SatelliteHostImages)
			if err != nil {
				return in, err
			}
			in.SatelliteHostImage = value
		}
		if len(in.SatelliteWorkerInstanceIDs) == 0 && in.SatelliteSSHKeyID == "" && in.SatelliteSSHPublicKeyPath == "" {
			values, err := publicKeyPaths()
			if err != nil {
				return in, err
			}
			if len(values) > 0 {
				in.SatelliteSSHPublicKeyPath, err = choose("Satellite SSH public key", values)
				if err != nil {
					return in, err
				}
			}
		}
	}
	return in, nil
}

func selectionMissingFields(in Inputs) []string {
	fields := make([]string, 0, 2)
	for _, field := range []struct{ name, value string }{{"target", in.Target}, {"provider", in.Provider}} {
		if field.value == "" {
			fields = append(fields, field.name)
		}
	}
	return fields
}

func normalizeVPCReuseInputs(in *Inputs, provider config.Provider) error {
	hasReuseIDs := in.VPCID != "" || len(in.SubnetIDs) > 0 || len(in.PublicGatewayIDs) > 0
	if provider != config.ProviderVPCGen2 && provider != config.ProviderSatellite {
		if hasReuseIDs {
			return errors.New("VPC reuse IDs are only supported by the vpc-gen2 or satellite provider")
		}
		return nil
	}

	vpcID, err := normalizeOptionalID("vpc ID", in.VPCID)
	if err != nil {
		return err
	}
	subnetIDs, err := normalizeIDList("subnet-id", in.SubnetIDs)
	if err != nil {
		return err
	}
	gatewayIDs, err := normalizeIDList("public-gateway-id", in.PublicGatewayIDs)
	if err != nil {
		return err
	}
	if provider == config.ProviderVPCGen2 && (len(subnetIDs) > 1 || len(gatewayIDs) > 1) {
		return errors.New("VPC mode accepts at most one subnet ID and one public gateway ID")
	}
	if provider == config.ProviderSatellite && ((len(subnetIDs) != 0 && len(subnetIDs) != 3) || (len(gatewayIDs) != 0 && len(gatewayIDs) != 3)) {
		return errors.New("Satellite mode requires exactly three subnet IDs and exactly three public gateway IDs when supplied")
	}
	in.VPCID = vpcID
	in.SubnetIDs = subnetIDs
	in.PublicGatewayIDs = gatewayIDs
	return nil
}

func normalizeSatelliteReuseInputs(in *Inputs, provider config.Provider) error {
	hasReuseIDs := in.SatelliteLocationID != "" || in.SatelliteSSHKeyID != "" || len(in.SatelliteWorkerInstanceIDs) > 0
	if provider != config.ProviderSatellite {
		if hasReuseIDs {
			return errors.New("Satellite location, SSH key, and worker instance IDs are only supported by the satellite provider")
		}
		return nil
	}
	locationID, err := normalizeOptionalID("satellite location ID", in.SatelliteLocationID)
	if err != nil {
		return err
	}
	keyID, err := normalizeOptionalID("satellite SSH key ID", in.SatelliteSSHKeyID)
	if err != nil {
		return err
	}
	workerIDs, err := normalizeIDList("satellite-worker-instance-id", in.SatelliteWorkerInstanceIDs)
	if err != nil {
		return err
	}
	if locationID != "" && strings.TrimSpace(in.SatelliteManagedFrom) != "" {
		return errors.New("satellite-managed-from cannot be used with satellite-location-id")
	}
	if keyID != "" && strings.TrimSpace(in.SatelliteSSHPublicKeyPath) != "" {
		return errors.New("satellite-ssh-key-id cannot be used with satellite-ssh-public-key")
	}
	if len(workerIDs) > 0 {
		if locationID == "" {
			return errors.New("satellite-worker-instance-id requires satellite-location-id")
		}
		if in.VPCID != "" || len(in.SubnetIDs) > 0 || len(in.PublicGatewayIDs) > 0 {
			return errors.New("VPC networking inputs cannot be used with satellite-worker-instance-id")
		}
		if keyID != "" || strings.TrimSpace(in.SatelliteSSHPublicKeyPath) != "" || strings.TrimSpace(in.SatelliteHostImage) != "" || strings.TrimSpace(in.SatelliteHostProfile) != "" {
			return errors.New("Satellite image, profile, and SSH key inputs cannot be used with satellite-worker-instance-id")
		}
	}
	in.SatelliteLocationID = locationID
	in.SatelliteSSHKeyID = keyID
	in.SatelliteWorkerInstanceIDs = workerIDs
	return nil
}

func normalizeOptionalID(name, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if value != "" && trimmed == "" {
		return "", fmt.Errorf("%s must not be blank", name)
	}
	return trimmed, nil
}

func normalizeIDList(name string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id, err := normalizeOptionalID(name, value)
		if err != nil || id == "" {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%s must not be blank", name)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("duplicate %s %q", name, id)
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func validVPCReuseValues(values Values) bool {
	inputs := Inputs{VPCID: values.VPCID, SubnetIDs: values.SubnetIDs, PublicGatewayIDs: values.PublicGatewayIDs}
	if err := normalizeVPCReuseInputs(&inputs, config.ProviderVPCGen2); err != nil {
		return false
	}
	return inputs.VPCID == values.VPCID && slices.Equal(inputs.SubnetIDs, values.SubnetIDs) && slices.Equal(inputs.PublicGatewayIDs, values.PublicGatewayIDs)
}

func canonicalizeSatelliteRecoveryNetworking(values *Values) error {
	if values.ClusterMode != "satellite" {
		return nil
	}
	inputs := Inputs{VPCID: values.VPCID, SubnetIDs: values.SubnetIDs, PublicGatewayIDs: values.PublicGatewayIDs}
	if err := normalizeVPCReuseInputs(&inputs, config.ProviderSatellite); err != nil {
		return err
	}
	values.VPCID = inputs.VPCID
	values.SubnetIDs = inputs.SubnetIDs
	values.PublicGatewayIDs = inputs.PublicGatewayIDs
	return nil
}

func validSatelliteReuseValues(values Values) bool {
	inputs := Inputs{VPCID: values.VPCID, SubnetIDs: values.SubnetIDs, PublicGatewayIDs: values.PublicGatewayIDs, SatelliteManagedFrom: values.SatelliteManagedFrom, SatelliteLocationID: values.SatelliteLocationID, SatelliteSSHKeyID: values.SatelliteSSHKeyID, SatelliteWorkerInstanceIDs: values.SatelliteWorkerInstanceIDs}
	if err := normalizeVPCReuseInputs(&inputs, config.ProviderSatellite); err != nil {
		return false
	}
	if err := normalizeSatelliteReuseInputs(&inputs, config.ProviderSatellite); err != nil {
		return false
	}
	if len(inputs.SatelliteWorkerInstanceIDs) > 0 && len(inputs.SatelliteWorkerInstanceIDs) != values.WorkerCount {
		return false
	}
	return inputs.VPCID == values.VPCID && slices.Equal(inputs.SubnetIDs, values.SubnetIDs) && slices.Equal(inputs.PublicGatewayIDs, values.PublicGatewayIDs) && inputs.SatelliteLocationID == values.SatelliteLocationID && inputs.SatelliteSSHKeyID == values.SatelliteSSHKeyID && slices.Equal(inputs.SatelliteWorkerInstanceIDs, values.SatelliteWorkerInstanceIDs)
}

func missingFields(in Inputs) []string {
	fields := make([]string, 0, 7)
	for _, field := range []struct{ name, value string }{{"platform", in.Platform}, {"version", in.Version}, {"resource-group", in.ResourceGroup}} {
		if field.value == "" {
			fields = append(fields, field.name)
		}
	}
	switch config.Provider(in.Provider) {
	case config.ProviderVPCGen2:
		for _, field := range []struct{ name, value string }{{"zone", in.Zone}, {"flavor", in.Flavor}} {
			if field.value == "" {
				fields = append(fields, field.name)
			}
		}
	case config.ProviderClassic:
		for _, field := range []struct{ name, value string }{{"datacenter", in.Datacenter}, {"machine-type", in.MachineType}, {"public-vlan-id", in.PublicVLANID}, {"private-vlan-id", in.PrivateVLANID}} {
			if field.value == "" {
				fields = append(fields, field.name)
			}
		}
	case config.ProviderSatellite:
		if len(in.SatelliteWorkerInstanceIDs) == 0 {
			for _, field := range []struct{ name, value string }{{"satellite-host-image", in.SatelliteHostImage}} {
				if field.value == "" {
					fields = append(fields, field.name)
				}
			}
		}
		if in.SatelliteLocationID == "" && in.SatelliteManagedFrom == "" {
			fields = append(fields, "satellite-managed-from")
		}
		if len(in.SatelliteWorkerInstanceIDs) == 0 && in.SatelliteSSHKeyID == "" && in.SatelliteSSHPublicKeyPath == "" {
			fields = append(fields, "satellite-ssh-public-key")
		}
		if len(in.SatelliteZones) != 3 {
			fields = append(fields, "satellite-zone")
		}
	}
	return fields
}

func requireClassicCredentials(environ []string) error {
	missing := make([]string, 0, 2)
	for _, name := range []string{"IAAS_CLASSIC_USERNAME", "IAAS_CLASSIC_API_KEY"} {
		if environmentValue(environ, name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("Classic operations require %s in the environment", strings.Join(missing, ", "))
	}
	return nil
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
	return generatedPrefixedName(truncate(owner, 10), now, suffix)
}

func generatedPrefixedName(prefix string, now time.Time, suffix string) string {
	return fmt.Sprintf("%s-%s-%s", prefix, now.UTC().Format("060102150405"), suffix)
}
func randomSuffix() (string, error) {
	bytes := make([]byte, 4)
	if _, err := cryptorand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate cluster name suffix: %w", err)
	}
	suffix := hex.EncodeToString(bytes)
	return suffix, nil
}
func truncate(value string, length int) string {
	if len(value) > length {
		return value[:length]
	}
	return value
}

func marshalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal runtime values: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}

// ReadPlanResult strictly validates a serialized plan handoff before a later operation uses it.
func ReadPlanResult(path string) (PlanResult, error) {
	if err := ictterraform.ValidateResultPath(path); err != nil {
		return PlanResult{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return PlanResult{}, fmt.Errorf("read plan result %q: %w", path, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var result PlanResult
	if err := decoder.Decode(&result); err != nil {
		return PlanResult{}, fmt.Errorf("decode plan result: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PlanResult{}, errors.New("plan result contains trailing JSON")
	}
	if result.Version != 1 {
		return PlanResult{}, fmt.Errorf("unsupported plan result version %d", result.Version)
	}
	if err := ictterraform.ValidateStateID(result.StateID); err != nil {
		return PlanResult{}, fmt.Errorf("invalid plan result lifecycle operation identifier: %w", err)
	}
	if err := result.Backend.Validate(); err != nil {
		return PlanResult{}, fmt.Errorf("invalid plan result backend: %w", err)
	}
	if err := ictterraform.ValidateResultPath(result.PlanPath); err != nil {
		return PlanResult{}, fmt.Errorf("invalid plan result plan path: %w", err)
	}
	if err := validateRecoveryForDestroy(result.Recovery); err != nil {
		return PlanResult{}, fmt.Errorf("invalid plan result recovery: %w", err)
	}
	values, err := recoveryValuesFromTFVars(result.Values, result.Recovery.SatelliteSSHPublicKeyFingerprint)
	if err != nil || !reflect.DeepEqual(values, result.Recovery.Values) {
		return PlanResult{}, errors.New("invalid plan result values")
	}
	tfvars, err := marshalJSON(result.Values)
	if err != nil || result.Recovery.TFVarsSHA256 != tfvarsSHA256(tfvars) {
		return PlanResult{}, errors.New("invalid plan result values")
	}
	return result, nil
}

func writeJSON(path string, value any) error {
	data, err := marshalJSON(value)
	if err != nil {
		return err
	}
	if err := ictterraform.AtomicWrite(path, data); err != nil {
		return fmt.Errorf("write runtime values: %w", err)
	}
	return nil
}

func tfvarsSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func validateRecoveryForDestroy(recovery RecoveryContext) error {
	if len(recovery.TFVarsSHA256) != sha256.Size*2 {
		return incompleteRecoveryContextError()
	}
	if _, err := hex.DecodeString(recovery.TFVarsSHA256); err != nil {
		return incompleteRecoveryContextError()
	}
	provider, err := validateRecoveryValues(recovery.Values, recovery.SatelliteSSHPublicKeyFingerprint)
	if err != nil {
		return incompleteRecoveryContextError()
	}
	target := config.Target{
		Providers:     []config.Provider{provider},
		DefaultRegion: recovery.Values.Region,
		Endpoints:     recovery.Endpoints,
	}
	resolved, err := (&config.Config{Targets: map[string]config.Target{recovery.Target: target}}).ResolveTarget(recovery.Target, nil)
	if err != nil || resolved.Name != recovery.Target {
		return incompleteRecoveryContextError()
	}
	return nil
}

func validateRecoveryValues(values Values, fingerprint string) (config.Provider, error) {
	if strings.TrimSpace(values.ResourceGroupName) == "" || values.WorkerCount < 1 || (values.Platform != "kubernetes" && values.Platform != "openshift") {
		return "", errors.New("invalid recovery values")
	}
	version, err := normalizeVersion(values.Platform, values.KubeVersion)
	if err != nil || version != values.KubeVersion {
		return "", errors.New("invalid recovery values")
	}

	switch values.ClusterMode {
	case "vpc":
		if !zonePattern.MatchString(values.Zone) || zoneRegion(values.Zone) != values.Region || !flavorPattern.MatchString(values.Flavor) || !vpcClusterPattern.MatchString(values.ClusterName) || !validVPCReuseValues(values) || fingerprint != "" || !emptyValues(values, "vpc") {
			return "", errors.New("invalid recovery values")
		}
		return config.ProviderVPCGen2, nil
	case "classic":
		if !datacenterPattern.MatchString(values.Datacenter) || !flavorPattern.MatchString(values.MachineType) || !vlanPattern.MatchString(values.PublicVLANID) || !vlanPattern.MatchString(values.PrivateVLANID) || !classicClusterPattern.MatchString(values.ClusterName) || fingerprint != "" || !emptyValues(values, "classic") {
			return "", errors.New("invalid recovery values")
		}
		return config.ProviderClassic, nil
	case "satellite":
		region, err := satelliteRegion(values.SatelliteZones)
		usingReusedWorkers := len(values.SatelliteWorkerInstanceIDs) > 0
		usingManagedKey := !usingReusedWorkers && values.SatelliteSSHKeyID != ""
		usingReusedLocation := values.SatelliteLocationID != ""
		if err != nil || region != values.Region || values.Platform != "openshift" || !satelliteClusterPattern.MatchString(values.ClusterName) || (usingReusedLocation && values.SatelliteManagedFrom != "") || (!usingReusedLocation && strings.TrimSpace(values.SatelliteManagedFrom) == "") || (!usingReusedWorkers && (strings.TrimSpace(values.SatelliteHostImage) == "" || !hostProfilePattern.MatchString(values.SatelliteHostProfile))) || (usingReusedWorkers && (values.SatelliteHostImage != "" || values.SatelliteHostProfile != "" || values.SatelliteSSHKeyID != "")) || (values.SatelliteWorkerOperatingSystem != "RHCOS" && values.SatelliteWorkerOperatingSystem != "REDHAT_8_64") || values.SatelliteSSHPublicKey != "" || (usingManagedKey && fingerprint != "") || (!usingManagedKey && !usingReusedWorkers && fingerprint == "") || (usingReusedWorkers && fingerprint != "") || (values.WorkerCount != 1 && values.WorkerCount != 3) || !validSatelliteReuseValues(values) || !emptyValues(values, "satellite") {
			return "", errors.New("invalid recovery values")
		}
		return config.ProviderSatellite, nil
	default:
		return "", errors.New("invalid recovery values")
	}
}

func emptyValues(values Values, provider string) bool {
	switch provider {
	case "vpc":
		return values.Datacenter == "" && values.MachineType == "" && values.PublicVLANID == "" && values.PrivateVLANID == "" && len(values.SatelliteZones) == 0 && values.SatelliteManagedFrom == "" && values.SatelliteLocationID == "" && values.SatelliteHostImage == "" && values.SatelliteHostProfile == "" && values.SatelliteSSHPublicKey == "" && values.SatelliteSSHKeyID == "" && len(values.SatelliteWorkerInstanceIDs) == 0 && values.SatelliteWorkerOperatingSystem == ""
	case "classic":
		return values.Zone == "" && values.Flavor == "" && values.VPCID == "" && len(values.SubnetIDs) == 0 && len(values.PublicGatewayIDs) == 0 && len(values.SatelliteZones) == 0 && values.SatelliteManagedFrom == "" && values.SatelliteLocationID == "" && values.SatelliteHostImage == "" && values.SatelliteHostProfile == "" && values.SatelliteSSHPublicKey == "" && values.SatelliteSSHKeyID == "" && len(values.SatelliteWorkerInstanceIDs) == 0 && values.SatelliteWorkerOperatingSystem == ""
	case "satellite":
		return values.Zone == "" && values.Flavor == "" && values.Datacenter == "" && values.MachineType == "" && values.PublicVLANID == "" && values.PrivateVLANID == ""
	default:
		return false
	}
}

func incompleteRecoveryContextError() error {
	return errIncompleteRecoveryContext
}

func recoveryValuesFromTFVars(values Values, fingerprint string) (Values, error) {
	if err := canonicalizeSatelliteRecoveryNetworking(&values); err != nil {
		return Values{}, errors.New("invalid Satellite recovery values")
	}
	if values.ClusterMode == "satellite" {
		if len(values.SatelliteWorkerInstanceIDs) > 0 {
			if values.SatelliteSSHPublicKey != "" || fingerprint != "" {
				return Values{}, errors.New("invalid Satellite recovery values")
			}
		} else if values.SatelliteSSHKeyID == "" {
			key, err := parseSSHPublicKey(values.SatelliteSSHPublicKey)
			if err != nil || key != values.SatelliteSSHPublicKey || sshPublicKeyFingerprint(key) != fingerprint {
				return Values{}, errors.New("invalid Satellite recovery values")
			}
		} else if values.SatelliteSSHPublicKey != "" || fingerprint != "" {
			return Values{}, errors.New("invalid Satellite recovery values")
		}
		values.SatelliteSSHPublicKey = ""
	}
	if _, err := validateRecoveryValues(values, fingerprint); err != nil {
		return Values{}, err
	}
	return values, nil
}
