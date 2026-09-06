// Package cli defines the Kong command grammar for ict.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/bevicted/ict/internal/config"
	ictterraform "github.com/bevicted/ict/internal/terraform"
	"github.com/bevicted/ict/internal/workflow"
)

// CLI is the root command grammar.
type CLI struct {
	Create  VPCCommand    `cmd:"" help:"Review and create a new cluster."`
	Destroy Destroy       `cmd:"" help:"Destroy only the currently managed cluster."`
	List    ListCommand   `cmd:"" aliases:"ls" help:"List known Terraform state workspaces."`
	Config  ConfigCommand `cmd:"" help:"Inspect effective configuration."`
}

// VPCCommand contains the transient inputs for create.
type VPCCommand struct {
	StateID                        string   `name:"state-id" help:"Terraform state workspace identifier." env:"ICT_STATE_ID" default:"default"`
	Config                         string   `help:"Target configuration file." env:"ICT_CONFIG"`
	Target                         string   `help:"Configured target name." env:"ICT_TARGET"`
	Provider                       string   `help:"Cluster provider (vpc-gen2, classic, or satellite)." env:"ICT_PROVIDER"`
	Platform                       string   `help:"Cluster platform (kubernetes or openshift)." env:"ICT_PLATFORM"`
	Version                        string   `help:"Kubernetes or OpenShift version." env:"ICT_VERSION"`
	ResourceGroup                  string   `help:"Existing resource group name." env:"ICT_RESOURCE_GROUP"`
	Zone                           string   `help:"VPC zone." env:"ICT_ZONE"`
	Flavor                         string   `help:"VPC worker flavor." env:"ICT_FLAVOR"`
	VPCID                          string   `name:"vpc-id" help:"Existing VPC Gen 2 ID to reuse." env:"ICT_VPC_ID"`
	SubnetIDs                      []string `name:"subnet-id" help:"Existing VPC Gen 2 subnet ID to reuse; VPC mode accepts one." env:"ICT_SUBNET_IDS" sep:","`
	PublicGatewayIDs               []string `name:"public-gateway-id" help:"Existing VPC Gen 2 public gateway ID to reuse; VPC mode accepts one." env:"ICT_PUBLIC_GATEWAY_IDS" sep:","`
	Datacenter                     string   `help:"Classic data center." env:"ICT_DATACENTER"`
	MachineType                    string   `help:"Classic worker machine type." env:"ICT_MACHINE_TYPE"`
	PublicVLANID                   string   `name:"public-vlan-id" help:"Existing numeric Classic public VLAN ID." env:"ICT_PUBLIC_VLAN_ID"`
	PrivateVLANID                  string   `name:"private-vlan-id" help:"Existing numeric Classic private VLAN ID." env:"ICT_PRIVATE_VLAN_ID"`
	SatelliteZones                 []string `name:"satellite-zone" help:"Satellite VPC host zone; repeat exactly three times." env:"ICT_SATELLITE_ZONES" sep:","`
	SatelliteManagedFrom           string   `name:"satellite-managed-from" help:"Satellite management location when ICT creates one." env:"ICT_SATELLITE_MANAGED_FROM"`
	SatelliteLocationID            string   `name:"satellite-location-id" help:"Existing healthy Satellite location ID to reuse." env:"ICT_SATELLITE_LOCATION_ID"`
	SatelliteHostImage             string   `name:"satellite-host-image" help:"Public RHEL image for Satellite hosts." env:"ICT_SATELLITE_HOST_IMAGE"`
	SatelliteHostProfile           string   `name:"satellite-host-profile" help:"VPC host profile for Satellite." env:"ICT_SATELLITE_HOST_PROFILE"`
	SatelliteSSHPublicKeyPath      string   `name:"satellite-ssh-public-key" help:"Path to an SSH public key for Satellite hosts." type:"path" env:"ICT_SATELLITE_SSH_PUBLIC_KEY"`
	SatelliteSSHKeyID              string   `name:"satellite-ssh-key-id" help:"Existing VPC SSH key ID for Satellite hosts." env:"ICT_SATELLITE_SSH_KEY_ID"`
	SatelliteWorkerInstanceIDs     []string `name:"satellite-worker-instance-id" help:"Existing Satellite worker VSI ID to assign; repeat once per worker." env:"ICT_SATELLITE_WORKER_INSTANCE_IDS" sep:","`
	SatelliteWorkerOperatingSystem string   `name:"satellite-worker-operating-system" help:"Satellite worker operating system." env:"ICT_SATELLITE_WORKER_OPERATING_SYSTEM"`
	WorkerCount                    int      `help:"Worker count (default: 1 for Kubernetes, 2 for OpenShift)." env:"ICT_WORKER_COUNT"`
	Owner                          string   `help:"Owner used when generating a name." env:"ICT_OWNER"`
	Name                           string   `help:"Explicit cluster name." env:"ICT_NAME"`
	AutoApprove                    bool     `help:"Apply without interactive approval." env:"ICT_AUTO_APPROVE"`
}

// Destroy deliberately accepts no replacement cluster inputs.
type Destroy struct {
	StateID string `name:"state-id" help:"Terraform state workspace identifier." env:"ICT_STATE_ID" default:"default"`
}

// ListCommand deliberately accepts no options.
type ListCommand struct{}

// ConfigCommand contains configuration inspection and mutation commands.
type ConfigCommand struct {
	Show ConfigShow `cmd:"" help:"Print the complete effective configuration as YAML."`
	Get  ConfigGet  `cmd:"" help:"Print an effective configuration value by dot path."`
	Set  ConfigSet  `cmd:"" help:"Set a stored configuration value after validating the complete result."`
	Edit ConfigEdit `cmd:"" help:"Edit or replace stored configuration without validation."`
}

// ConfigShow contains options for config show.
type ConfigShow struct {
	Config string `help:"Target configuration file." env:"ICT_CONFIG"`
}

// ConfigGet contains options for config get.
type ConfigGet struct {
	Path   string `arg:"" name:"path" help:"Dot-separated effective configuration path."`
	Config string `help:"Target configuration file." env:"ICT_CONFIG"`
}

// ConfigSet contains options for config set.
type ConfigSet struct {
	Path   string `arg:"" name:"path" help:"Dot-separated stored configuration path."`
	Value  string `arg:"" name:"yaml-value" help:"Inline YAML value, or - to read one YAML value from stdin."`
	Config string `help:"Target configuration file." env:"ICT_CONFIG"`
}

// ConfigEdit contains options for config edit.
type ConfigEdit struct {
	Config string `help:"Target configuration file." env:"ICT_CONFIG"`
}

// Parse parses args with Kong's standard CLI and ICT_* environment mapping.
func Parse(args []string) (*kong.Context, *CLI, error) {
	cli := &CLI{}
	ctx, err := kong.New(cli, kong.Name("ict"), kong.Description("IBM Cloud Terraformer"))
	if err != nil {
		return nil, nil, err
	}
	parsed, err := ctx.Parse(args)
	return parsed, cli, err
}

// Runner wires lifecycle and configuration command dependencies.
type Runner struct {
	Workflow workflow.Runner
	Config   config.Runner
	Stdout   io.Writer
}

// Run dispatches the selected command.
func Run(ctx context.Context, parsed *kong.Context, command *CLI) error {
	runner := Runner{}
	if err := runner.Run(ctx, parsed, command); err != nil {
		return err
	}
	return nil
}

// Run dispatches the selected command through its appropriate runner.
func (r Runner) Run(ctx context.Context, parsed *kong.Context, command *CLI) error {
	switch parsed.Command() {
	case "create":
		runner, err := r.lifecycle(command.Create.StateID)
		if err != nil {
			return err
		}
		return runner.Create(ctx, command.Create.inputs())
	case "destroy":
		runner, err := r.lifecycle(command.Destroy.StateID)
		if err != nil {
			return err
		}
		return runner.Destroy(ctx)
	case "list":
		return r.list()
	case "config show":
		return r.Config.Show(command.Config.Show.Config)
	case "config get <path>":
		return r.Config.Get(command.Config.Get.Config, command.Config.Get.Path)
	case "config set <path> <yaml-value>":
		return r.Config.Set(command.Config.Set.Config, command.Config.Set.Path, command.Config.Set.Value)
	case "config edit":
		return r.Config.Edit(ctx, command.Config.Edit.Config)
	default:
		return nil
	}
}

func (r Runner) list() error {
	workspaces, err := ictterraform.ListWorkspaces()
	if err != nil {
		return err
	}
	for _, workspace := range workspaces {
		if _, err := fmt.Fprintln(r.stdout(), workspace); err != nil {
			return fmt.Errorf("write state workspace list: %w", err)
		}
	}
	return nil
}

func (r Runner) stdout() io.Writer {
	if r.Stdout != nil {
		return r.Stdout
	}
	return os.Stdout
}

func (r Runner) lifecycle(stateID string) (workflow.Runner, error) {
	workspace, err := ictterraform.Workspace(stateID)
	if err != nil {
		return workflow.Runner{}, err
	}
	runner := r.Workflow
	runner.Workspace = workspace
	return runner, nil
}

func (c VPCCommand) inputs() workflow.Inputs {
	return workflow.Inputs{ConfigPath: c.Config, Target: c.Target, Provider: c.Provider, Platform: c.Platform, Version: c.Version, ResourceGroup: c.ResourceGroup, Zone: c.Zone, Flavor: c.Flavor, VPCID: c.VPCID, SubnetIDs: c.SubnetIDs, PublicGatewayIDs: c.PublicGatewayIDs, Datacenter: c.Datacenter, MachineType: c.MachineType, PublicVLANID: c.PublicVLANID, PrivateVLANID: c.PrivateVLANID, SatelliteZones: c.SatelliteZones, SatelliteManagedFrom: c.SatelliteManagedFrom, SatelliteLocationID: c.SatelliteLocationID, SatelliteHostImage: c.SatelliteHostImage, SatelliteHostProfile: c.SatelliteHostProfile, SatelliteSSHPublicKeyPath: c.SatelliteSSHPublicKeyPath, SatelliteSSHKeyID: c.SatelliteSSHKeyID, SatelliteWorkerInstanceIDs: c.SatelliteWorkerInstanceIDs, SatelliteWorkerOperatingSystem: c.SatelliteWorkerOperatingSystem, WorkerCount: c.WorkerCount, Owner: c.Owner, Name: c.Name, AutoApprove: c.AutoApprove}
}
