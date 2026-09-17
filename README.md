# ICT - IBM Cloud Terraformer

ICT is a Go command-line tool for planning, applying, and destroying one short-lived IBM Cloud Kubernetes, OpenShift, or Satellite cluster through Terraform. Terraform state is stored in IBM Cloud Object Storage (COS) through Terraform's S3 backend.

## Prerequisites

- Go 1.23 or newer to build from source.
- Terraform 1.5 or newer on `PATH`.
- IBM Cloud CLI on `PATH`, authenticated for the selected target.
- `fzf` only when a planning command must interactively select omitted inputs.

Build from a source checkout:

```sh
go build -o ict .
```

## Configuration

Lifecycle planning requires a strict, single-document YAML configuration. ICT resolves it in this order:

1. `--config PATH`
2. `ICT_CONFIG`
3. `${XDG_CONFIG_HOME:-~/.config}/ict/config.yaml`

Start with the public template:

```sh
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/ict"
cp config.example.yaml "${XDG_CONFIG_HOME:-$HOME/.config}/ict/config.yaml"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/ict/config.yaml"
```

The schema is version 1. Every target needs IAM, Container Service, Global Tagging, Resource Management, and Resource Controller endpoints. VPC Gen 2 and Satellite targets also need the VPC endpoint template; Satellite targets also need Satellite and Satellite Config endpoints.

Standard IBM Cloud endpoint environment variables override the selected profile after validation: `IBMCLOUD_IAM_API_ENDPOINT`, `IBMCLOUD_CS_API_ENDPOINT`, `IBMCLOUD_GT_API_ENDPOINT`, `IBMCLOUD_RESOURCE_MANAGEMENT_API_ENDPOINT`, `IBMCLOUD_RESOURCE_CONTROLLER_API_ENDPOINT`, `IBMCLOUD_IS_NG_API_ENDPOINT`, `IBMCLOUD_SATELLITE_API_ENDPOINT`, and `IBMCLOUD_SATELLITE_CONFIG_API_ENDPOINT`.

Use `config show`, `config get`, `config set`, and `config edit` to inspect or manage this configuration. These commands use the same configuration discovery order. `config show` prints canonical YAML, and `config get` prints one effective value by dot path.

## Split lifecycle

Automation uses three commands:

1. `plan` resolves the request once and writes frozen, non-secret metadata.
2. `apply` validates that metadata and performs a new Terraform plan and noninteractive apply.
3. `destroy` validates the same metadata and asks the remote backend to destroy, even when no local state or prior workspace exists.

Each command takes an opaque lifecycle ID matching `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. The ID is embedded in frozen planning metadata and must match later operations. Local Terraform directories are task-local implementation details, not lifecycle state or recovery inputs.

### Backend configuration

`--backend-config` names an absolute strict JSON file containing only non-secret COS S3 backend identity and settings:

```json
{
  "version": 1,
  "bucket": "ict-state-bucket",
  "key": "allocations/allocation-123.tfstate",
  "region": "us-south",
  "endpoint": "https://s3.us-south.cloud-object-storage.appdomain.cloud",
  "skip_credentials_validation": true,
  "skip_metadata_api_check": true,
  "skip_region_validation": true,
  "skip_requesting_account_id": true,
  "force_path_style": true
}
```

HMAC credentials remain environment variables, for example `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. They must not be included in the backend file, command arguments, frozen context, or result files. `use_lockfile: true` is rejected because ICT supports Terraform 1.5+, while that S3 setting requires Terraform 1.10.

### Plan

`plan` requires the cluster inputs, an absolute backend file, and an absolute result path:

```sh
ict plan allocation-123 \
  --backend-config /run/ict/backend.json \
  --result-file /run/ict/context.json \
  --config "$HOME/.config/ict/config.yaml" \
  --target example --provider vpc-gen2 --platform kubernetes --version 1.31 \
  --resource-group example-resource-group --zone us-south-1 --flavor bx2.2x8
```

It initializes the S3 backend and produces a disposable Terraform plan without applying or prompting. The result is strict versioned frozen metadata containing canonical values, recovery context, backend identity, lifecycle ID, and a task-local binary-plan path for private review tooling. The binary plan itself is never serialized in the result and is not an apply input.

Generated names, defaults, endpoint selection, provider ownership choices, and the canonical tfvars digest are resolved only by `plan`. VPC Gen 2, Classic, and Satellite recovery safeguards remain encoded in those frozen values. Existing VPC networking, Satellite infrastructure, and externally owned resources continue to be represented as Terraform data sources and are not deleted by destroy.

When ICT is used by Servitor, Slack approval authorizes this frozen configuration, not an immutable Terraform action list. `apply` deliberately makes a fresh plan, so cloud or provider drift between review and apply can change the resulting actions. The review plan is ephemeral and is neither saved for approval nor accepted as an apply input.

### Apply

`apply` accepts no replacement cluster inputs. It requires matching frozen context and backend files, a result file, and `--auto-approve`:

```sh
ict apply allocation-123 \
  --context-file /run/ict/context.json \
  --backend-config /run/ict/backend.json \
  --result-file /run/ict/apply-result.json \
  --auto-approve
```

ICT rejects omitted `--auto-approve`, malformed, unknown, or trailing JSON, changed lifecycle IDs, backend mismatch, changed canonical values, recomputed defaults or names, and credential fields before it initializes Terraform. It reconstructs canonical Terraform files in fresh task-local storage, initializes the exact frozen S3 backend, and runs `terraform apply -input=false -no-color -auto-approve` with the frozen tfvars. This intentionally makes a new Terraform plan; it does not consume or compare the disposable review plan.

### Optional admin export

A caller can request a best-effort endpoint-appropriate admin bundle only while applying:

```sh
ict apply allocation-123 \
  --context-file /run/ict/context.json \
  --backend-config /run/ict/backend.json \
  --result-file /run/ict/apply-result.json \
  --auth-manifest-file /run/ict/auth-manifest.json \
  --auth-output-dir /run/ict/auth \
  --auto-approve
```

Both auth paths are required together. ICT applies infrastructure first, then uses isolated companion state at `<backend-key>.auth` to inspect the actual cluster endpoint. The optional frozen private-policy flags belong to `plan`, not `apply`: `--auth-allocation-uid`, `--auth-vpn-server-id`, `--auth-secrets-manager-id`, `--auth-secrets-manager-region`, `--auth-secret-group-id`, `--auth-certificate-template`, `--auth-issuer`, and `--auth-ttl`. They are non-secret and all-or-none; later operations use only the frozen context. The private `kubeconfig.yaml` is atomically written with mode `0600`; it embeds its certificate authority and client credentials and rejects exec plugins, tokens, and local credential references. The manifest is bounded non-secret JSON containing only availability and artifact names.

A public endpoint writes exactly `kubeconfig.yaml` and reports `mode: public`. For a private-only VPC, the frozen plan inputs may include an allocation UID plus existing VPN, Secrets Manager, template, issuer, group, region, and TTL policy. ICT then uses the isolated companion state at `<backend-key>.auth` to issue only that allocation certificate with the pinned IBM provider, retrieves the generic VPN profile and private admin config, and writes exactly `kubeconfig.yaml` plus `client.ovpn`. The manifest reports `mode: vpn` and the actual certificate expiry, never credential material. Classic clusters retain their public-only kubeconfig export; only private VPC clusters can receive a VPN bundle. Satellite, missing private VPC metadata, or a missing private policy return safe `unsupported` without acquisition.

The VPN profile must contain inline server trust and cannot request login/password credentials, external certificate files, scripts, plugins, or management hooks. ICT validates a client-auth certificate, PKCS8 key match, actual unexpired expiry, and self-contained kubeconfig before either private artifact is retained. Retrieval, validation, timeout, cancellation, or output failures return `unavailable` without changing the successful infrastructure apply result; partial bundles are removed. ICT does not retry, renew, or recover a failed export. Destroy uses the original frozen policy and companion state with refresh disabled, deletes only the allocation certificate, and treats absent/partial state or a provider 404 as best-effort cleanup that never prevents infrastructure cleanup. Deletion is not certificate revocation.

### Destroy

`destroy` also accepts no replacement cluster inputs:

```sh
ict destroy allocation-123 \
  --context-file /run/ict/context.json \
  --backend-config /run/ict/backend.json \
  --result-file /run/ict/destroy-result.json
```

ICT reconstructs the validated frozen tfvars in fresh task-local storage, initializes the remote backend, and runs Terraform destroy with `-auto-approve`. It never treats a missing local state file, missing workspace, inaccessible backend, or ambiguous remote state as successful cleanup. Terraform's remote-backend result is the only cleanup success signal, including a successful no-resource destroy. If companion certificate cleanup cannot run, the successful destroy result records only `"auth_cleanup":"failed"` and emits `ict: auth cleanup unavailable`; neither message includes provider details or claims certificate revocation.

### Result files

Successful apply and destroy write one bounded JSON result file:

```json
{"version":1,"operation":"apply","workspace":"/private/task-local/workspace"}
```

The path is private task-local data that permits a wrapper to run Terraform inspection for sanitized reporting. Result files contain no raw Terraform plan, Terraform state, backend credentials, or subprocess diagnostics. On a Terraform or backend failure, ICT returns an error and does not write a successful operation result.
