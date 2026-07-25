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
exclude:
  namespaces:
    - kube-system
  labels:
    - app=legacy
    - tier in (internal,batch)
```

Namespace exclusions are exact names. Label exclusions use Kubernetes selector
syntax, and a resource is excluded when any configured selector matches.

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

The `summary.total_resources_scanned` field reports the aggregate number of
Kubernetes objects the audit examined across all auditors. It is a scan-operation
count, not a distinct-object count: an object inspected by more than one auditor
(for example a pod is examined by the pod-security, image, and service-account
auditors) is counted once per auditor.


## Architecture

- **Single binary** — no dependencies, no cluster-side components
- **Read-only** — only needs get/list RBAC permissions
- **Concurrent** — parallel auditors with bounded concurrency
- **Extensible** — add new auditors by implementing the `Auditor` interface


## Project Status

**Status: Alpha** | v0.2.0
