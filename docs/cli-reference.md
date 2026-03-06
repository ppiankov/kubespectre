## Install

```bash
# Homebrew
brew install ppiankov/tap/kubespectre

# Go
go install github.com/ppiankov/kubespectre/cmd/kubespectre@latest

# Binary: download from GitHub Releases
# https://github.com/ppiankov/kubespectre/releases
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

**Status: Alpha** | v0.1.0

