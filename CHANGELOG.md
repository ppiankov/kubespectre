# Changelog

## [Unreleased]

### Added
- New PersistentVolume data-retention auditor: flags a `Released`-phase volume with `reclaimPolicy: Retain` older than `--stale-days` as `STALE_RELEASED_VOLUME` (`medium` severity) -- the underlying cloud volume is not deleted and may still hold the former workload's data

## [0.4.4] - 2026-07-25

### Fixed
- SARIF output now declares rules for `HOSTPATH_VOLUME`, `DANGEROUS_CAPABILITY`, and `PRIVILEGE_ESCALATION_ALLOWED`, which previously appeared in results with no matching rule declaration

## [0.4.3] - 2026-07-25

### Added
- Pod-security auditing now also flags hostPath volume mounts (`HOSTPATH_VOLUME`), containers adding dangerous Linux capabilities (`DANGEROUS_CAPABILITY`, configurable via `dangerous_capabilities`), and containers that do not explicitly disable privilege escalation (`PRIVILEGE_ESCALATION_ALLOWED`)

### Changed
- `STALE_SECRET` and `UNUSED_SECRET_MOUNT` findings on secrets carrying a recognized controller-managed annotation marker (defaulting to `cert-manager.io/` and `external-secrets.io/`) are now reported at `medium` severity instead of `high`, configurable via `managed_secret_markers` and `disable_managed_secret_downranking`

## [0.4.2] - 2026-07-25

### Added
- RBAC auditing now covers namespaced `Role` and `RoleBinding` objects in addition to cluster-scoped RBAC: wildcard-granting `Role` definitions and `RoleBinding` grants of an admin-equivalent ClusterRole (`cluster-admin`/`admin`/`edit`) to a non-system subject are now flagged

### Fixed
- `total_resources_scanned` now excludes objects suppressed by configured exclusions for the RBAC, pod-security, secret, image, and service-account auditors, consistent with the network-policy auditor's existing evaluated-only count

## [0.4.1] - 2026-07-25

### Fixed
- `total_resources_scanned` in the scan summary now reflects the number of cluster objects each auditor examined instead of always reporting `0`
- Network policy scans count only namespaces actually evaluated toward `total_resources_scanned`, excluding skipped, excluded, and out-of-scope namespaces
- Cluster-edge join keys can no longer be emitted except through the gated projection path, so the `--include-edge-join-keys` default-off guarantee holds structurally

### Changed
- Release workflow hardened: per-tag run serialization, a pre-build gate that requires a `CHANGELOG.md` entry matching the release tag, and a source-contract test that pins these guards and the asset-before-formula publish order

### Documentation
- Documented that excluded namespaces are absent from the artifact entirely (no findings, no cluster edges, no coverage entry)
- Documented the per-auditor scan-count semantic of `total_resources_scanned`
- README: SpectreHub links now point to `https://spectrehub.dev`; removed the retired Go Report Card badge

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
