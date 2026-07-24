# Changelog

## [0.4.0] - 2026-07-24

### Added
- Opt-in join-key fields on `cluster_positive_edges` for IAM correlation: `--include-edge-join-keys` (default off) adds `namespace`, `service_account`, `role_arn`, and workload/pod attribution to each edge so downstream tools can correlate cluster evidence to IAM. When disabled, edges remain sanitized to `type` and `observed_at` only.

## [0.3.0] - 2026-07-23

### Added
- Configurable scan exclusions in `.kubespectre.yaml` (`exclude.namespaces`, `exclude.labels`): exclude namespaces by exact name or resources by Kubernetes label selector; excluded resources are omitted from findings and evidence
- Windows release builds (amd64 and arm64), verified in CI

### Changed
- Text report findings are now sorted by severity (critical first) instead of scan order
- Explicit `--format`, `--severity-min`, `--timeout`, and `--stale-days` flags now take precedence over config-file values even when set to a default; an explicit empty `--namespace` correctly means all namespaces

## [0.2.0] - 2026-07-23

### Added
- Positive cluster-side IAM correlation edges in the audit JSON envelope (`cluster_positive_edges`): observed ServiceAccount role annotations, workload references, and pod references
- RBAC-proven namespace coverage metadata (`coverage`): a namespace is reported `complete` only when a SelfSubjectAccessReview definitively allows listing ServiceAccounts, otherwise `unknown`
- Edge output is sanitized: only the observation category and source-collection timestamp are serialized; raw identity and absence are never emitted

## [0.1.0] - 2026-02-28

### Added
- CLI commands: audit, rbac, init, version
- 7 security auditors: RBAC, pod security, network policy, secrets, service accounts, image provenance, audit logging
- Report formatters: text, JSON, SARIF, SpectreHub
- Configuration file support (.kubespectre.yaml)
- CI pipeline (test, lint, build)
- GoReleaser + Homebrew tap integration
