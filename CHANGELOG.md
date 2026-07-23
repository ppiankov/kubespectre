# Changelog

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
