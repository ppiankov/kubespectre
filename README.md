# kubespectre

[![CI](https://github.com/ppiankov/kubespectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/kubespectre/actions/workflows/ci.yml)

**Kubernetes security posture auditor**

kubespectre audits Kubernetes cluster security: RBAC permissions, pod security standards, network policies, secret lifecycle, service account hygiene, image provenance, and audit logging. It produces actionable findings with severity levels for CI/CD gating and compliance reporting.

## What it is

- Read-only security posture scanner for Kubernetes clusters
- Produces findings in text, JSON, SARIF, and SpectreHub formats
- Integrates with GitHub Security tab via SARIF upload
- Part of the [Spectre](https://spectrehub.dev) infrastructure audit family

## What it is NOT

- Not a runtime security monitor (no eBPF, no agents)
- Not a remediation tool (read-only, never modifies cluster resources)
- Not a replacement for OPA/Gatekeeper (those enforce policy; this audits posture)
- Not a vulnerability scanner (use Trivy/Grype for CVEs)

## What it audits

| Resource | Signal | Severity |
|----------|--------|----------|
| RBAC ClusterRoleBindings | Wildcard verbs/resources, cluster-admin to non-system SAs | critical |
| Pod Security Standards | Privileged containers, hostNetwork, hostPID | critical |
| Network Policies | Namespaces with no NetworkPolicy (default-allow-all) | high |
| Secrets | Stale secrets, unused secret mounts | high |
| Service Accounts | Default SA used by workloads, automountServiceAccountToken | medium |
| Image Provenance | No image digest pinning, untrusted registries | medium |
| Audit Logging | Audit policy missing or incomplete | high |

## Quick Start

```bash
# Install
go install github.com/ppiankov/kubespectre/cmd/kubespectre@latest

# Generate config and RBAC policy
kubespectre init

# Apply RBAC (optional, for service account usage)
kubectl apply -f kubespectre-rbac.yaml

# Run full audit
kubespectre audit

# RBAC-only audit
kubespectre rbac

# JSON output for CI/CD
kubespectre audit --format json -o report.json

# SARIF for GitHub Security tab
kubespectre audit --format sarif -o results.sarif
```

## Usage

### Commands

```bash
kubespectre audit    # Full security posture audit
kubespectre rbac     # RBAC-only analysis
kubespectre init     # Generate sample config and RBAC policy
kubespectre version  # Print version information
```

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
```

## Architecture

- **Single binary** — no dependencies, no cluster-side components
- **Read-only** — only needs get/list RBAC permissions
- **Concurrent** — parallel auditors with bounded concurrency
- **Extensible** — add new auditors by implementing the `Auditor` interface

## Project Status

**Status: Alpha** | Pre-release

## License

MIT
