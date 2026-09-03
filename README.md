# ICT - IBM Cloud Terraformer

ICT is a Go command-line tool for planning, creating, and explicitly destroying one short-lived IBM Cloud Kubernetes, OpenShift, or Satellite cluster. Terraform remains the provisioning engine. ICT supports macOS and Linux.

## Prerequisites

- Go 1.23 or newer to build from source.
- Terraform 1.5 or newer on `PATH`.
- IBM Cloud CLI on `PATH`, authenticated for the selected target.
- `fzf` only when ICT must interactively select omitted inputs in a terminal. Fully specified commands do not invoke or require `fzf` or IBM Cloud CLI discovery.

Install the latest release directly:

```sh
go install github.com/bevicted/ict@latest
```

Or build from a source checkout:

```sh
go build -o ict .
```

Then run the binary as `./ict` or place it on `PATH` as `ict`.

## Configuration

`plan` and `create` require a strict, single-document YAML configuration. ICT resolves it in this order:

1. `--config PATH`
2. `ICT_CONFIG`
3. `${XDG_CONFIG_HOME:-~/.config}/ict/config.yaml`

Start with the public template:

```sh
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/ict"
cp config.example.yaml "${XDG_CONFIG_HOME:-$HOME/.config}/ict/config.yaml"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/ict/config.yaml"
```

Replace every `example.invalid` value with endpoints for your target. The schema is version 1:

```yaml
version: 1
targets:
  example:
    providers: [vpc-gen2, classic, satellite]
    default_region: us-south
    endpoints:
      iam: https://iam.example.invalid
      container_service: https://containers.example.invalid
      global_tagging: https://global-tagging.example.invalid
      resource_management: https://resource-management.example.invalid
      resource_controller: https://resource-controller.example.invalid
      vpc: https://vpc.{region}.example.invalid
      satellite: https://satellite.example.invalid
      satellite_config: https://satellite-config.example.invalid
```

Target names are lowercase letters, digits, and hyphens. Every profile is validated, including profiles not selected by a command. Unknown and duplicate fields, extra YAML documents, unsupported versions, invalid URLs, invalid regions, duplicate providers, and incomplete provider endpoints are rejected. All profiles require IAM, Container Service, Global Tagging, Resource Management, and Resource Controller endpoints. VPC Gen 2 and Satellite profiles also require the `vpc` template; Satellite profiles additionally require `satellite` and `satellite_config`.

Standard IBM Cloud endpoint variables override the selected profile after validation: `IBMCLOUD_IAM_API_ENDPOINT`, `IBMCLOUD_CS_API_ENDPOINT`, `IBMCLOUD_GT_API_ENDPOINT`, `IBMCLOUD_RESOURCE_MANAGEMENT_API_ENDPOINT`, `IBMCLOUD_RESOURCE_CONTROLLER_API_ENDPOINT`, `IBMCLOUD_IS_NG_API_ENDPOINT`, `IBMCLOUD_SATELLITE_API_ENDPOINT`, and `IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT`. There is no endpoint command-line override.

## Lifecycle

Use `plan` to review Terraform changes, `create` to apply them, and `destroy` only to destroy the saved active cluster. `create` and `destroy` use Terraform auto-approval, so review a plan first.

A fully specified VPC Gen 2 plan looks like this:

```sh
ict plan \
  --config "$HOME/.config/ict/config.yaml" \
  --target example \
  --provider vpc-gen2 \
  --platform kubernetes \
  --version 1.31 \
  --resource-group example-resource-group \
  --zone us-south-1 \
  --flavor bx2.2x8 \
  --name example-cluster
```

The same inputs work with `create`. If `--name` is omitted, ICT generates a name from `--owner` (or `USER`) plus a timestamp and random suffix. All options can also be supplied through their matching `ICT_*` environment variable shown by `ict plan --help`.

Provider-specific inputs are:

- VPC Gen 2: `--zone` and `--flavor`. The region is derived from the zone.
- Classic: `--datacenter`, `--machine-type`, `--public-vlan-id`, and `--private-vlan-id`. Both VLAN IDs must name existing numeric VLANs. ICT does not create or manage Classic VLANs. Classic commands also require `IAAS_CLASSIC_USERNAME` and `IAAS_CLASSIC_API_KEY` in the environment.
- Satellite: repeat `--satellite-zone` exactly three times in one region, then provide `--satellite-managed-from`, `--satellite-host-image`, and `--satellite-ssh-public-key`. Satellite requires OpenShift. `--satellite-host-profile` defaults to `bx2-4x16`, and `--satellite-worker-operating-system` defaults to `RHCOS`.

`--worker-count` defaults to 1, except Classic OpenShift defaults to 3. Satellite accepts only 1 or 3 workers. Satellite creates a location, three control-plane hosts, and worker hosts, so it can incur substantial VPC, compute, and Satellite costs. Confirm all selected zones, image, profile, capacity, and pricing before `create`.

When target, provider, or any required provider input is omitted, ICT may use IBM Cloud CLI JSON discovery and `fzf` only from an interactive terminal. Without a terminal or `fzf`, it returns the same missing-input error rather than guessing.

```sh
ict destroy
```

`destroy` accepts no replacement cluster inputs. It uses only the saved recovery context and values, refuses an empty state, and refuses plan/create inputs that do not match an existing managed state. Keep the state workspace and its private files available until the cluster is safely destroyed.

## State, recovery, and upgrades

ICT has one active Terraform workspace at `${XDG_STATE_HOME:-~/.local/state}/ict/terraform`. It holds Terraform state, provider runtime data, generated values, and recovery context with private permissions. Do not add it to source control, copy it into issue reports, or delete it while resources may exist. ICT does not automatically import legacy workspaces; preserve any old recovery material as data and establish a complete current recovery context before attempting a destructive action.

Each ICT binary materializes its embedded Terraform files into that workspace. A newer binary can therefore change the Terraform configuration applied to existing state. After every upgrade, run and review `ict plan` before `create`; do not assume an upgrade is behaviorally neutral.
