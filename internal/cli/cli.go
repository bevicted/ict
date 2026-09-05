// Package cli defines the Kong command grammar for ict.
package cli

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/bevicted/ict/internal/config"
	"github.com/bevicted/ict/internal/workflow"
)

// CLI is the root command grammar.
type CLI struct {
	Plan    VPCCommand    `cmd:"" help:"Create a non-mutating Terraform plan."`
	Create  VPCCommand    `cmd:"" help:"Create or safely resume a cluster."`
	Destroy Destroy       `cmd:"" help:"Destroy only the currently managed cluster."`
	Config  ConfigCommand `cmd:"" help:"Inspect effective configuration."`
}

// VPCCommand contains the transient inputs shared by plan and create.
type VPCCommand struct {
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
	SatelliteManagedFrom           string   `name:"satellite-managed-from" help:"Satellite management location." env:"ICT_SATELLITE_MANAGED_FROM"`
	SatelliteHostImage             string   `name:"satellite-host-image" help:"Public RHEL image for Satellite hosts." env:"ICT_SATELLITE_HOST_IMAGE"`
	SatelliteHostProfile           string   `name:"satellite-host-profile" help:"VPC host profile for Satellite." env:"ICT_SATELLITE_HOST_PROFILE"`
	SatelliteSSHPublicKeyPath      string   `name:"satellite-ssh-public-key" help:"Path to an SSH public key for Satellite hosts." type:"path" env:"ICT_SATELLITE_SSH_PUBLIC_KEY"`
	SatelliteWorkerOperatingSystem string   `name:"satellite-worker-operating-system" help:"Satellite worker operating system." env:"ICT_SATELLITE_WORKER_OPERATING_SYSTEM"`
	WorkerCount                    int      `help:"Worker count (default: 1 for Kubernetes, 2 for OpenShift)." env:"ICT_WORKER_COUNT"`
	Owner                          string   `help:"Owner used when generating a name." env:"ICT_OWNER"`
	Name                           string   `help:"Explicit cluster name." env:"ICT_NAME"`
}

// Destroy deliberately accepts no replacement cluster inputs.
type Destroy struct{}

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
}

// Run dispatches the selected command.
func Run(ctx context.Context, parsed *kong.Context, command *CLI) error {
	return (Runner{}).Run(ctx, parsed, command)
}

// Run dispatches the selected command through its appropriate runner.
func (r Runner) Run(ctx context.Context, parsed *kong.Context, command *CLI) error {
	switch parsed.Command() {
	case "plan":
		return r.Workflow.Plan(ctx, command.Plan.inputs())
	case "create":
		return r.Workflow.Create(ctx, command.Create.inputs())
	case "destroy":
		return r.Workflow.Destroy(ctx)
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

func (c VPCCommand) inputs() workflow.Inputs {
	return workflow.Inputs{ConfigPath: c.Config, Target: c.Target, Provider: c.Provider, Platform: c.Platform, Version: c.Version, ResourceGroup: c.ResourceGroup, Zone: c.Zone, Flavor: c.Flavor, VPCID: c.VPCID, SubnetIDs: c.SubnetIDs, PublicGatewayIDs: c.PublicGatewayIDs, Datacenter: c.Datacenter, MachineType: c.MachineType, PublicVLANID: c.PublicVLANID, PrivateVLANID: c.PrivateVLANID, SatelliteZones: c.SatelliteZones, SatelliteManagedFrom: c.SatelliteManagedFrom, SatelliteHostImage: c.SatelliteHostImage, SatelliteHostProfile: c.SatelliteHostProfile, SatelliteSSHPublicKeyPath: c.SatelliteSSHPublicKeyPath, SatelliteWorkerOperatingSystem: c.SatelliteWorkerOperatingSystem, WorkerCount: c.WorkerCount, Owner: c.Owner, Name: c.Name}
}
