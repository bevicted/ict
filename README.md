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

`create` requires a strict, single-document YAML configuration. ICT resolves it in this order:

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

### Inspect configuration

Use `config show` to print the complete effective configuration, or `config get` to print one effective value by dot path:

```sh
ict config show [--config PATH]
ict config get targets.example.endpoints.vpc [--config PATH]
```

These commands use the same configuration discovery order as lifecycle commands: `--config`, `ICT_CONFIG`, then `${XDG_CONFIG_HOME:-~/.config}/ict/config.yaml`. `show` prints canonical YAML. `get` prints scalar values without YAML quoting and with one trailing newline; maps and lists are printed as YAML. List items can be addressed by their zero-based index, for example `targets.example.providers.0`.

The output is effective, not necessarily stored: ICT expands each target's VPC endpoint with that target's `default_region` and applies recognized endpoint environment overrides. Only the version 1 configuration fields are displayed; credential environment variables and password-manager data are not read or displayed.

### Update stored configuration

Use `config set` to change one stored value by dot path:

```sh
ict config set targets.example.default_region eu-gb [--config PATH]
ict config set targets.example.providers - [--config PATH] <<'YAML'
- vpc-gen2
- classic
YAML
```

The value is one YAML value. Inline scalars and collections retain YAML typing, so quote a value when it must be a string rather than a YAML boolean, number, or null. A value exactly equal to `-` reads that YAML value from standard input.

`set` accepts the update only when the resulting complete document strictly decodes and passes all ICT configuration validation. It can add an omitted field or a complete target, and can repair an incomplete stored document when that one update makes it valid. Malformed source YAML, invalid values or paths, and invalid resulting configurations leave the source unchanged.

`set` updates the stored document, whereas `show` and `get` display the effective configuration. The update preserves comments, mapping order, scalar styles, and unrelated formatting outside the replaced subtree; formatting within the replaced subtree can change.

### Edit stored configuration

Use `config edit` to replace the stored document without parsing or validating it:

```sh
ict config edit [--config PATH]
```

When standard input is a terminal, ICT creates missing parent directories with mode `0700` and a missing configuration file with mode `0600`, then runs the command named by `$EDITOR` against that actual file. `$EDITOR` can include arguments, for example `EDITOR="vi -f"`. A successful editor exit is a successful edit even if it leaves malformed or incomplete YAML; edits made before an editor failure are not rolled back.

When standard input is not a terminal, `config edit` reads the complete input and atomically replaces the selected file with those exact nonempty bytes, using mode `0600`. This also creates missing private parent directories. Empty input is rejected without creating a missing file or changing an existing one. Piped input is never parsed or semantically validated, so use `config set` when ICT must verify a configuration update.

`config edit` uses the same `--config`, `ICT_CONFIG`, and XDG discovery order as the other configuration commands.

## Lifecycle

Use `create` to generate and display one Terraform plan, then apply that exact saved plan after confirmation. Each lifecycle action requires its state workspace ID as the first positional argument: `ict create ID` or `ict destroy ID`. Interactive `create` applies only when the response is the literal `yes`. Use `--auto-approve` or `ICT_AUTO_APPROVE=true` for non-interactive callers; without either, a non-interactive create fails before creating a workspace.

A fully specified VPC Gen 2 create looks like this:

```sh
ict create example \
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

If `--name` is omitted, ICT generates a name from `--owner` (or `USER`) plus a timestamp and random suffix. All create flags can also be supplied through their matching `ICT_*` environment variable shown by `ict create --help`. ICT saves the reviewed plan at `.cluster/create.tfplan` with mode `0600`; treat it as sensitive and leave it in place until `ict destroy ID` removes the workspace.

### Reuse VPC Gen 2 networking

VPC Gen 2 and Satellite plans can reuse existing infrastructure by immutable ID: `--vpc-id` (`ICT_VPC_ID`), repeatable `--subnet-id` (`ICT_SUBNET_IDS`, comma-separated), and repeatable `--public-gateway-id` (`ICT_PUBLIC_GATEWAY_IDS`, comma-separated). VPC mode accepts at most one subnet ID and one gateway ID; Satellite mode accepts either no IDs or exactly three unique IDs in each repeated group. These options are not accepted for Classic clusters.

ICT reads supplied VPCs, subnets, and gateways as Terraform data sources. It never imports or destroys them. A supplied subnet or gateway infers its VPC. When an explicit VPC is also supplied, all IDs must identify resources in that VPC and supplied subnet/gateway zones must match `--zone`. An existing subnet attachment is external and remains untouched. For an unattached supplied subnet, ICT creates and later removes only the attachment it establishes.

Omitted IDs create only a dependency the cluster still needs. Complete reuse creates the cluster, but no VPC, subnet, or gateway:

```sh
ict create example --provider vpc-gen2 --platform kubernetes --version 1.31 \
  --resource-group example-resource-group --zone us-south-1 --flavor bx2.2x8 \
  --vpc-id vpc-existing --subnet-id subnet-existing \
  --public-gateway-id gateway-existing --name example-cluster
```

Mixed ownership is also supported. This plan reads the existing subnet, infers its VPC, and creates only a gateway and its attachment when the subnet is unattached:

```sh
ICT_SUBNET_IDS=subnet-existing ict create example --provider vpc-gen2 --platform kubernetes \
  --version 1.31 --resource-group example-resource-group --zone us-south-1 \
  --flavor bx2.2x8 --name example-cluster
```

### Reuse Satellite infrastructure

Satellite accepts the same VPC, subnet, and public-gateway IDs. Supply either no IDs or exactly three unordered subnet IDs and exactly three unordered gateway IDs. ICT reads their provider-reported zones and requires one matching subnet and gateway in every explicit `--satellite-zone`; it never relies on input order. Supplied objects are data sources and survive `destroy`. Existing subnet-gateway attachments remain external. ICT creates and later removes only an attachment it needs for an unattached subnet.

Use `--satellite-location-id` (`ICT_SATELLITE_LOCATION_ID`) for a location that already has its control plane. It must have at least three attached hosts and cover all requested zones. ICT reads it and creates no location or control-plane VSIs or assignments. The IBM provider waits for the location to become `normal` during `apply`, or fails before issuing the cluster-create request; the location data source does not expose that state, so `plan` cannot validate it independently. In this mode omit `--satellite-managed-from`; it is required only when ICT creates a location.

For ICT-managed worker VSIs, use either `--satellite-ssh-key-id` (`ICT_SATELLITE_SSH_KEY_ID`) or `--satellite-ssh-public-key`, not both. A key ID is read by ID and is never managed. Image, profile, and one key input are required only when ICT creates worker VSIs. All supplied IDs and ownership choices are saved in the private Terraform values and recovery context, so a later `destroy` preserves externally owned VPC networking, keys, locations, and VSIs.

Example complete reuse with managed workers:

```sh
ict create example --provider satellite --platform openshift --version 4.17 \
  --resource-group example-resource-group \
  --satellite-zone us-south-1 --satellite-zone us-south-2 --satellite-zone us-south-3 \
  --vpc-id vpc-existing --subnet-id subnet-3 --subnet-id subnet-1 --subnet-id subnet-2 \
  --public-gateway-id gateway-2 --public-gateway-id gateway-3 --public-gateway-id gateway-1 \
  --satellite-location-id location-existing --satellite-host-image rhel-8-synthetic \
  --satellite-ssh-key-id key-existing --name example-satellite
```

### Reuse Satellite worker VSIs

For an existing worker group, repeat `--satellite-worker-instance-id` (`ICT_SATELLITE_WORKER_INSTANCE_IDS`, comma-separated) exactly once for every `--worker-count`. IDs are unordered: ICT reads the plural VSI inventory, resolves every ID exactly once, and uses each VSI's reported zone rather than the argument position. The IDs require `--satellite-location-id`; every VSI must already be registered in that location as an unassigned `ready` host. ICT creates the cluster and manages one `ibm_satellite_host` assignment per supplied VSI. Destroy removes those assignments, but does not manage or delete the location or VSIs.

A reused worker group has no VPC, subnet, gateway, SSH key, image, profile, or attach-script consumer. Omit those creation inputs; ICT rejects supplied networking, image, profile, and SSH-key inputs rather than silently ignoring them. Explicit `--satellite-zone` values and the worker operating system remain required for cluster topology. This fully reused plan creates only the cluster and its worker assignments:

```sh
ict create example --provider satellite --platform openshift --version 4.17 \
  --resource-group example-resource-group --worker-count 3 \
  --satellite-zone us-south-1 --satellite-zone us-south-2 --satellite-zone us-south-3 \
  --satellite-location-id location-existing \
  --satellite-worker-instance-id worker-vsi-3 \
  --satellite-worker-instance-id worker-vsi-1 \
  --satellite-worker-instance-id worker-vsi-2 \
  --name example-satellite
```

Provider-specific inputs are:

- VPC Gen 2: `--zone` and `--flavor`. The region is derived from the zone.
- Classic: `--datacenter`, `--machine-type`, `--public-vlan-id`, and `--private-vlan-id`. Both VLAN IDs must name existing numeric VLANs. ICT does not create or manage Classic VLANs. Classic commands also require `IAAS_CLASSIC_USERNAME` and `IAAS_CLASSIC_API_KEY` in the environment.
- Satellite: repeat `--satellite-zone` exactly three times in one region. New locations require `--satellite-managed-from`; reused locations use `--satellite-location-id` instead. Managed worker VSIs require `--satellite-host-image` and either `--satellite-ssh-key-id` or `--satellite-ssh-public-key`; existing worker IDs replace all of those inputs. Satellite requires OpenShift. `--satellite-host-profile` defaults to `bx2-4x16` only for managed VSIs, and `--satellite-worker-operating-system` defaults to `RHCOS`.

`--worker-count` defaults to 1 for Kubernetes and 2 for OpenShift. Satellite is the exception and accepts only 1 or 3 workers. Satellite creates a location, three control-plane hosts, and worker hosts, so it can incur substantial VPC, compute, and Satellite costs. Confirm all selected zones, image, profile, capacity, and pricing before `create`.

When target, provider, or any required provider input is omitted, ICT may use IBM Cloud CLI JSON discovery and `fzf` only from an interactive terminal. Without a terminal or `fzf`, it returns the same missing-input error rather than guessing.

```sh
ict destroy example
```

`destroy` accepts only the required state ID positional argument and no replacement cluster inputs. When no Terraform state file exists, it removes the selected retained workspace directly. When state exists, it uses only the saved recovery context and values, runs Terraform destroy, and deletes the complete workspace only after that succeeds. Any Terraform, recovery, or cleanup failure preserves the workspace for diagnosis and retry.

## State, recovery, and upgrades

Each lifecycle action uses `${XDG_STATE_HOME:-~/.local/state}/ict/ID`, where `ID` is its required positional state ID. IDs are case-sensitive ASCII strings matching `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; invalid, empty, path-like, hidden, Unicode, and overlength IDs are rejected. Different IDs are sibling workspaces, for example `.../ict/default` and `.../ict/slack-user-42`. A state ID is one-shot: once create reserves its workspace, every later create for that ID fails until explicit `ict destroy ID` removes it. A workspace holds Terraform state, provider runtime data, generated values, recovery context, and the sensitive saved plan with private permissions. Terraform state is authoritative for managed resources. Do not add workspaces to source control, copy them into issue reports, or delete them while resources may exist. Failed initialization, planning, or apply attempts remain in `ict list` for diagnosis and must also be removed with `ict destroy ID`.

`ict list` and `ict ls` are the same read-only workspace inventory. They print valid immediate real-directory IDs in lexical order, one ID per line. Retained failed create attempts are included without inspecting Terraform state; files, symlinks, invalid names, and nested directories are ignored. If the ICT state root is absent, the command prints nothing and does not create it.

Each ICT binary materializes its embedded Terraform files into that workspace. A newer binary can therefore change the Terraform configuration used by a later destroy; do not assume an upgrade is behaviorally neutral.
