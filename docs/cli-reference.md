## Install

```bash
# Homebrew
brew install ppiankov/tap/kubespectre

# Go
go install github.com/ppiankov/kubespectre/cmd/kubespectre@latest

# Binary: download from GitHub Releases
# https://github.com/ppiankov/kubespectre/releases
```

### Windows

Download `kubespectre_<version>_windows_<arch>.zip` from
[GitHub Releases](https://github.com/ppiankov/kubespectre/releases), extract it,
and verify the executable in PowerShell:

```powershell
.\kubespectre.exe version
```


## Usage

### Commands

```bash
kubespectre audit    # Full security posture audit
kubespectre rbac     # RBAC-only analysis
kubespectre init     # Generate sample config and RBAC policy
kubespectre version  # Print version information
```

RBAC auditing covers both cluster-scoped and namespaced RBAC: it flags
`ClusterRole` **and** namespaced `Role` definitions that grant wildcard verbs or
resources, and `ClusterRoleBinding` **and** namespaced `RoleBinding` grants of an
admin-equivalent ClusterRole (`cluster-admin`/`admin`/`edit`) to a non-system
subject.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | auto | Path to kubeconfig file |
| `--context` | current | Kubernetes context to use |
| `-n, --namespace` | all | Namespace to audit |
| `--format` | text | Output format: text, json, sarif, spectrehub |
| `-o, --output` | stdout | Output file path |
| `--severity-min` | low | Minimum severity: critical, high, medium, low |
| `--stale-days` | 90 | Threshold for stale secrets (days) |
| `--include-edge-join-keys` | false | Opt in to include join-key fields in `cluster_positive_edges` |
| `--check-default-deny-baseline` | false | Flag namespaces whose NetworkPolicies do not match a default-deny baseline shape (convention lint, no severity) |
| `--timeout` | 5m | Audit timeout |
| `-v, --verbose` | false | Enable verbose logging |

### Configuration

Create `.kubespectre.yaml` (or run `kubespectre init`):

```yaml
stale_days: 90
severity_min: low
format: text
timeout: 5m
trusted_registries:
  - gcr.io/my-project
  - us-docker.pkg.dev/my-project
dangerous_capabilities:
  - NET_ADMIN
  - SYS_ADMIN
  - SYS_PTRACE
  - NET_RAW
managed_secret_markers:
  - cert-manager.io/
  - external-secrets.io/
disable_managed_secret_downranking: false
exclude:
  namespaces:
    - kube-system
  labels:
    - app=legacy
    - tier in (internal,batch)
```

Namespace exclusions are exact names. Label exclusions use Kubernetes selector
syntax, and a resource is excluded when any configured selector matches.

### Pod security checks

The pod-security auditor flags: `HOST_NETWORK` (hostNetwork), `HOST_PID`
(hostPID), `PRIVILEGED_CONTAINER` (a container's `securityContext.privileged`
set true), `HOSTPATH_VOLUME` (any pod volume mounting a host filesystem path),
`DANGEROUS_CAPABILITY` (a container adding a Linux capability from the
configured `dangerous_capabilities` list, defaulting to `NET_ADMIN`,
`SYS_ADMIN`, `SYS_PTRACE`, `NET_RAW`), and `PRIVILEGE_ESCALATION_ALLOWED` (a
non-privileged container that does not explicitly set
`allowPrivilegeEscalation: false` — the Kubernetes default is `true`). A
privileged container is not also flagged for privilege escalation, since
privileged mode already implies it.

### Stale released volumes

The PersistentVolume auditor flags `STALE_RELEASED_VOLUME` (`medium` severity)
for any PersistentVolume in `Released` phase with `persistentVolumeReclaimPolicy:
Retain` whose age (since `status.lastPhaseTransitionTime`, falling back to
`creationTimestamp` when unset) exceeds `--stale-days`. A `Released` volume
means its bound PersistentVolumeClaim was deleted; with `reclaimPolicy: Retain`
the underlying cloud volume (EBS/PD/managed disk) is not deleted and may still
hold the former workload's data. A volume with `reclaimPolicy: Delete`, or one
younger than the threshold, is not flagged. The finding's metadata includes
`reclaim_policy`, `storage_class`, `capacity`, and (when backed by a CSI
driver) `csi_driver`/`volume_handle` so the operator can locate the underlying
cloud volume. This check is fully local to the Kubernetes API -- it does not
call any cloud-provider API and does not confirm the underlying volume still
exists or estimate its cost.

### Secret severity for controller-managed secrets

A `STALE_SECRET` or `UNUSED_SECRET_MOUNT` finding on a secret carrying an
annotation key prefixed by a configured `managed_secret_markers` entry
(defaulting to `cert-manager.io/` and `external-secrets.io/`) is reported at
`medium` severity instead of `high`, and its message notes the recognized
marker: age alone does not indicate an unrotated or forgotten credential for a
secret a controller actively owns, and lack of a pod mount does not mean
unused for a secret consumed via a non-pod-mount path (Ingress `tls.secretName`,
webhook `caBundle` injection). Neither finding is ever suppressed, only
down-ranked. Set `disable_managed_secret_downranking: true` to opt back into
uniform `high` severity for both finding types regardless of markers, or set
`managed_secret_markers` to your own list to recognize other controllers.

An excluded namespace is treated as fully out of scope: it produces **no
findings, no `cluster_positive_edges`, and no `coverage` entry**. It is absent
from the artifact entirely — it is not marked "excluded" and carries no scope
proof. Consumers correlating on completeness should read an excluded namespace
as absent evidence, not as a scanned-but-clean namespace.

### JSON output

With `--format json`, the audit envelope may include two additional fields:

- `cluster_positive_edges` — observed IAM correlation signals (ServiceAccount role annotations, workload references, pod references). By default each edge serializes only its observation category and source-collection timestamp; raw identity is never emitted.

Use `--include-edge-join-keys` to opt in to non-sensitive join keys for downstream correlation:

- `namespace` and `service_account` for all edges
- `role_arn` for service-account annotation edges
- `workload_kind` and `workload_name` for workload edges
- `pod_name` for pod edges

Join-key output is disabled by default.
- `coverage` — per-namespace scope proof. A namespace is `complete` only when a SelfSubjectAccessReview confirms permission to list ServiceAccounts in it; otherwise it is `unknown`. Uncovered namespaces produce no absence claim.

Every `CLUSTER_ADMIN_BINDING` finding's `metadata` carries `subject_kind` (`ServiceAccount`/`User`/`Group`) and `subject_liveness`, a closed four-value enum: `confirmed_exists` (the ServiceAccount was found), `confirmed_absent` (the ServiceAccount does not currently exist -- the binding is inert but reactivates full `cluster-admin` the instant anything recreates that namespace/ServiceAccount name), `check_failed` (the existence check itself failed, e.g. an RBAC denial -- never treated as absence), or `not_checkable` (User/Group subjects -- Kubernetes has no API to check these). Severity is always `critical` regardless of `subject_liveness`; only the message text changes, and only for `confirmed_absent`.

- `environment_observations.networking` — a per-object inventory of DaemonSets whose container images match a known NetworkPolicy-capable CNI component (AWS VPC CNI's network-policy agent, Calico, Cilium). Each `fingerprint_matches[]` entry carries `implementation_hint`, the exact `resource` (kind/namespace/name), `matched_signals`, an object-local `rollout` state (`running`/`rollout_incomplete`/`not_running`/`readiness_unknown`), and (AWS only) `enforcing_mode` (`mode_literal:<value>`/`mode_none`/`mode_via_ref_unresolved`/`mode_absent`). `limitations[]` is always present and `observation_errors[]` records a failed lookup distinctly from a genuinely empty result. **This is a per-object observation list only** -- it makes no cluster-level enforcement, capability, or restrictiveness claim, multiple matching components (e.g. both AWS and Calico) are reported independently with no reduction, and it never alters `MISSING_NETWORK_POLICY` or any other finding.

### Default-deny baseline lint (opt-in)

With `--check-default-deny-baseline`, a namespace whose NetworkPolicies do not match a default-deny baseline shape is flagged as `DEFAULT_DENY_BASELINE_NOT_DETECTED`. A namespace matches the baseline only if some policy with an empty `podSelector` (`{}`, selecting every pod) denies a direction (an empty rule list for that direction) **and** no `{}`-selecting policy allows that direction unconditionally (a rule with no `from`/`to`/`ports` restriction) -- this correctly handles the case where a second `{}`-selecting policy's allow-all rule silently overrides an otherwise-correct default-deny policy. This is a **convention lint, not a vulnerability finding**: it carries no severity, and its message never claims the namespace is insecure -- a namespace secured entirely by narrow per-pod allow-list policies (no `{}`-selecting policy at all) is a valid, intentional architecture that will also not match this shape. Disabled by default, and entirely decoupled from the `environment_observations.networking` CNI-capability plane above.

The `summary.total_resources_scanned` field reports the aggregate number of
Kubernetes objects the audit examined across all auditors. It is a scan-operation
count, not a distinct-object count: an object inspected by more than one auditor
(for example a pod is examined by the pod-security, image, and service-account
auditors) is counted once per auditor. Objects suppressed by configured
`exclude.namespaces`/`exclude.labels` exclusions are not counted as examined by
any auditor.


## Architecture

- **Single binary** — no dependencies, no cluster-side components
- **Read-only** — only needs get/list RBAC permissions
- **Concurrent** — parallel auditors with bounded concurrency
- **Extensible** — add new auditors by implementing the `Auditor` interface


## Project Status

**Status: Alpha** | v0.2.0
