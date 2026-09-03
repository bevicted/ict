// Package cli defines the Kong command grammar for ict.
package cli

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/bevicted/ict/internal/workflow"
)

// CLI is the root command grammar.
type CLI struct {
	Plan    VPCCommand `cmd:"" help:"Create a non-mutating Terraform plan."`
	Create  VPCCommand `cmd:"" help:"Create or safely resume a cluster."`
	Destroy Destroy    `cmd:"" help:"Destroy only the currently managed cluster."`
}

// VPCCommand contains the transient inputs shared by plan and create.
type VPCCommand struct {
	Config        string `help:"Target configuration file." type:"path" env:"ICT_CONFIG"`
	Target        string `help:"Configured target name." env:"ICT_TARGET"`
	Provider      string `help:"Cluster provider (vpc-gen2 or classic)." env:"ICT_PROVIDER"`
	Platform      string `help:"Cluster platform (kubernetes or openshift)." env:"ICT_PLATFORM"`
	Version       string `help:"Kubernetes or OpenShift version." env:"ICT_VERSION"`
	ResourceGroup string `help:"Existing resource group name." env:"ICT_RESOURCE_GROUP"`
	Zone          string `help:"VPC zone." env:"ICT_ZONE"`
	Flavor        string `help:"VPC worker flavor." env:"ICT_FLAVOR"`
	Datacenter    string `help:"Classic data center." env:"ICT_DATACENTER"`
	MachineType   string `help:"Classic worker machine type." env:"ICT_MACHINE_TYPE"`
	PublicVLANID  string `name:"public-vlan-id" help:"Existing numeric Classic public VLAN ID." env:"ICT_PUBLIC_VLAN_ID"`
	PrivateVLANID string `name:"private-vlan-id" help:"Existing numeric Classic private VLAN ID." env:"ICT_PRIVATE_VLAN_ID"`
	WorkerCount   int    `help:"Worker count." env:"ICT_WORKER_COUNT"`
	Owner         string `help:"Owner used when generating a name." env:"ICT_OWNER"`
	Name          string `help:"Explicit cluster name." env:"ICT_NAME"`
}

// Destroy deliberately accepts no replacement cluster inputs.
type Destroy struct{}

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

// Run dispatches the selected command through the workflow.
func Run(ctx context.Context, parsed *kong.Context, command *CLI) error {
	runner := workflow.Runner{}
	switch parsed.Command() {
	case "plan":
		return runner.Plan(ctx, command.Plan.inputs())
	case "create":
		return runner.Create(ctx, command.Create.inputs())
	case "destroy":
		return runner.Destroy(ctx)
	default:
		return nil
	}
}

func (c VPCCommand) inputs() workflow.Inputs {
	return workflow.Inputs{ConfigPath: c.Config, Target: c.Target, Provider: c.Provider, Platform: c.Platform, Version: c.Version, ResourceGroup: c.ResourceGroup, Zone: c.Zone, Flavor: c.Flavor, Datacenter: c.Datacenter, MachineType: c.MachineType, PublicVLANID: c.PublicVLANID, PrivateVLANID: c.PrivateVLANID, WorkerCount: c.WorkerCount, Owner: c.Owner, Name: c.Name}
}
