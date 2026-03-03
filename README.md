# kubespectre

[![CI](https://github.com/ppiankov/kubespectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/kubespectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/kubespectre)](https://goreportcard.com/report/github.com/ppiankov/kubespectre)

**kubespectre** — Kubernetes security posture auditor. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Audits RBAC permissions, pod security standards, and network policies
- Detects stale secrets, unused service accounts, and image provenance issues
- Checks audit logging configuration and namespace isolation
- Each finding includes severity for CI/CD gating and compliance reporting
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a runtime security monitor — no eBPF, no agents
- Not a remediation tool — read-only, never modifies cluster resources
- Not a replacement for OPA/Gatekeeper — audits posture, not policy enforcement
- Not a vulnerability scanner — use Trivy/Grype for CVEs

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install kubespectre
```

### From source

```sh
git clone https://github.com/ppiankov/kubespectre.git
cd kubespectre
make build
```

### Usage

```sh
kubespectre audit --kubeconfig ~/.kube/config --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `kubespectre audit` | Audit cluster security posture |
| `kubespectre version` | Print version |

## SpectreHub integration

kubespectre feeds Kubernetes security findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool kubespectre
```

## Safety

kubespectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your cluster resources.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://github.com/ppiankov)
