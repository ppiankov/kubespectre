package k8s

import (
	"encoding/json"
	"time"
)

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityRank returns a numeric rank for sorting (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// MeetsSeverityMin returns true if s meets or exceeds the minimum severity.
func MeetsSeverityMin(s, min Severity) bool {
	return SeverityRank(s) >= SeverityRank(min)
}

// ParseSeverity converts a string to Severity, defaulting to low.
func ParseSeverity(s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityLow
	}
}

// FindingID identifies the type of security issue detected.
type FindingID string

const (
	FindingWildcardRBAC          FindingID = "WILDCARD_RBAC"
	FindingClusterAdminBinding   FindingID = "CLUSTER_ADMIN_BINDING"
	FindingPrivilegedContainer   FindingID = "PRIVILEGED_CONTAINER"
	FindingHostNetwork           FindingID = "HOST_NETWORK"
	FindingHostPID               FindingID = "HOST_PID"
	FindingMissingNetworkPolicy  FindingID = "MISSING_NETWORK_POLICY"
	FindingUnencryptedSecrets    FindingID = "UNENCRYPTED_SECRETS"
	FindingUnusedSecretMount     FindingID = "UNUSED_SECRET_MOUNT"
	FindingStaleSecret           FindingID = "STALE_SECRET"
	FindingDefaultServiceAccount FindingID = "DEFAULT_SERVICE_ACCOUNT"
	FindingAutomountToken        FindingID = "AUTOMOUNT_TOKEN"
	FindingNoImageDigest         FindingID = "NO_IMAGE_DIGEST"
	FindingUntrustedRegistry     FindingID = "UNTRUSTED_REGISTRY"
	FindingMissingAuditPolicy    FindingID = "MISSING_AUDIT_POLICY"
)

// Finding represents a single security posture issue.
type Finding struct {
	ID           FindingID      `json:"id"`
	Severity     Severity       `json:"severity"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Namespace    string         `json:"namespace"`
	Cluster      string         `json:"cluster"`
	Message      string         `json:"message"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// WO-24: ClusterPositiveEdgeProjection is the machine-readable edge schema.
// WO-29: identity join keys are UNEXPORTED so no external caller can populate
// them with a struct literal and bypass the join-key gate. Only Type and
// ObservedAt are exported; identity serializes solely when the constructor
// ProjectClusterPositiveEdge was asked to include join keys. This restores the
// WO-6 "prevent structurally" boundary that the earlier exported-field design
// downgraded to "control-by-option".
type ClusterPositiveEdgeProjection struct {
	Type       ClusterPositiveEdgeType `json:"type"`
	ObservedAt time.Time               `json:"observed_at"`

	// WO-29: identity is gated behind the constructor, never a literal.
	includeJoinKeys bool
	namespace       string
	serviceAccount  string
	roleARN         string
	workloadKind    string
	workloadName    string
	podName         string
}

// WO-29: sanitizedEdgeProjection is the default serialization — no identity.
type sanitizedEdgeProjection struct {
	Type       ClusterPositiveEdgeType `json:"type"`
	ObservedAt time.Time               `json:"observed_at"`
}

// WO-29: joinKeyEdgeProjection is the opt-in serialization carrying join keys.
// Field names and omitempty match the pre-WO-29 wire schema exactly so consumers
// are unaffected.
type joinKeyEdgeProjection struct {
	Type           ClusterPositiveEdgeType `json:"type"`
	ObservedAt     time.Time               `json:"observed_at"`
	Namespace      string                  `json:"namespace,omitempty"`
	ServiceAccount string                  `json:"service_account,omitempty"`
	RoleARN        string                  `json:"role_arn,omitempty"`
	WorkloadKind   string                  `json:"workload_kind,omitempty"`
	WorkloadName   string                  `json:"workload_name,omitempty"`
	PodName        string                  `json:"pod_name,omitempty"`
}

// WO-29: MarshalJSON emits identity join keys only when the constructor enabled
// them. A zero-value or externally built projection can never leak identity
// because the gate and the identity fields are both unexported.
func (p ClusterPositiveEdgeProjection) MarshalJSON() ([]byte, error) {
	if !p.includeJoinKeys {
		return json.Marshal(sanitizedEdgeProjection{
			Type:       p.Type,
			ObservedAt: p.ObservedAt,
		})
	}
	return json.Marshal(joinKeyEdgeProjection{
		Type:           p.Type,
		ObservedAt:     p.ObservedAt,
		Namespace:      p.namespace,
		ServiceAccount: p.serviceAccount,
		RoleARN:        p.roleARN,
		WorkloadKind:   p.workloadKind,
		WorkloadName:   p.workloadName,
		PodName:        p.podName,
	})
}

// ScanResult holds all findings from scanning a cluster.
// WO-6: Carry positive observations and independently proven coverage in scan results.
type ScanResult struct {
	Findings             []Finding             `json:"findings"`
	Errors               []string              `json:"errors,omitempty"`
	ClusterPositiveEdges []ClusterPositiveEdge `json:"cluster_positive_edges,omitempty"` // WO-6: serialize only each edge's sanitized projection.
	NamespaceCoverage    []NamespaceCoverage   `json:"coverage,omitempty"`               // WO-6: keep completeness separate from positive observations.
	ResourcesScanned     int                   `json:"resources_scanned"`
}

// AuditConfig holds parameters that control auditing behavior.
type AuditConfig struct {
	Namespace         string
	StaleDays         int
	SeverityMin       Severity
	TrustedRegistries []string
	Cluster           string
	Exclusions        Exclusions // WO-19: immutable operator-declared scan boundary.
}

// WO-6: ClusterPositiveEdgeType is closed to the three ratified positive observations.
type ClusterPositiveEdgeType string

// WO-6: Restrict emitted edge categories to ratified positive observations.
const (
	ServiceAccountRoleAnnotationObserved ClusterPositiveEdgeType = "SERVICEACCOUNT_ROLE_ANNOTATION_OBSERVED"
	WorkloadReferenceObserved            ClusterPositiveEdgeType = "WORKLOAD_REFERENCE_OBSERVED"
	PodReferenceObserved                 ClusterPositiveEdgeType = "POD_REFERENCE_OBSERVED"
)

// WO-6: ClusterPositiveEdge is sealed so other packages cannot add absence or verdict variants.
type ClusterPositiveEdge interface {
	Type() ClusterPositiveEdgeType
	Cluster() string
	Namespace() string
	ServiceAccount() string
	ObservedAt() time.Time
	positiveClusterObservation()
}

// WO-6: clusterPositiveEdgeBase keeps raw correlation identity out of default serialization.
type clusterPositiveEdgeBase struct {
	cluster        string    // WO-6: correlation identity stays private.
	namespace      string    // WO-6: correlation identity stays private.
	serviceAccount string    // WO-6: correlation identity stays private.
	observedAt     time.Time // WO-6: read-time freshness remains available to projections.
}

// WO-6: clusterPositiveEdgeProjection exposes observation kind and freshness, never identity.
type clusterPositiveEdgeProjection struct {
	Type       ClusterPositiveEdgeType `json:"type"`        // WO-6: the ratified observation category.
	ObservedAt time.Time               `json:"observed_at"` // WO-6: source-collection time, not upload time.
}

// WO-6: marshalClusterPositiveEdge deliberately excludes raw correlation identity.
func marshalClusterPositiveEdge(edgeType ClusterPositiveEdgeType, observedAt time.Time) ([]byte, error) {
	return json.Marshal(clusterPositiveEdgeProjection{Type: edgeType, ObservedAt: observedAt})
}

// WO-24: ProjectClusterPositiveEdge exposes a stable machine-readable projection.
func ProjectClusterPositiveEdge(
	edge ClusterPositiveEdge,
	includeJoinKeys bool,
) ClusterPositiveEdgeProjection {
	if edge == nil {
		return ClusterPositiveEdgeProjection{}
	}
	projection := ClusterPositiveEdgeProjection{
		Type:       edge.Type(),
		ObservedAt: edge.ObservedAt(),
	}
	if !includeJoinKeys {
		return projection
	}

	// WO-29: only the constructor may open the join-key gate and set identity.
	projection.includeJoinKeys = true
	projection.namespace = edge.Namespace()
	projection.serviceAccount = edge.ServiceAccount()

	if roleARN, ok := ServiceAccountRoleAnnotationEvidence(edge); ok {
		projection.roleARN = roleARN
	}
	if kind, name, ok := WorkloadReferenceEvidence(edge); ok {
		projection.workloadKind = kind
		projection.workloadName = name
	}
	if podName, ok := PodReferenceEvidence(edge); ok {
		projection.podName = podName
	}
	return projection
}

// WO-24: ProjectClusterPositiveEdges maps sealed edges into report projections.
func ProjectClusterPositiveEdges(
	edges []ClusterPositiveEdge,
	includeJoinKeys bool,
) []ClusterPositiveEdgeProjection {
	projected := make([]ClusterPositiveEdgeProjection, 0, len(edges))
	for _, edge := range edges {
		projected = append(projected, ProjectClusterPositiveEdge(edge, includeJoinKeys))
	}
	return projected
}

// WO-6: these accessors expose identity only to explicit in-process correlation.
func (e clusterPositiveEdgeBase) Cluster() string { return e.cluster }

// WO-6: Expose namespace identity only for explicit in-process correlation.
func (e clusterPositiveEdgeBase) Namespace() string { return e.namespace }

// WO-6: Expose service-account identity only for explicit in-process correlation.
func (e clusterPositiveEdgeBase) ServiceAccount() string { return e.serviceAccount }

// WO-6: Expose the source-collection instant for freshness checks.
func (e clusterPositiveEdgeBase) ObservedAt() time.Time { return e.observedAt }

// WO-6: newClusterPositiveEdgeBase structurally rejects incomplete observations.
func newClusterPositiveEdgeBase(
	cluster, namespace, serviceAccount string,
	observedAt time.Time,
) (clusterPositiveEdgeBase, bool) {
	if cluster == "" || namespace == "" || serviceAccount == "" || observedAt.IsZero() {
		return clusterPositiveEdgeBase{}, false
	}
	return clusterPositiveEdgeBase{
		cluster:        cluster,
		namespace:      namespace,
		serviceAccount: serviceAccount,
		observedAt:     observedAt,
	}, true
}

// WO-6: serviceAccountRoleAnnotationObservedEdge can represent only observed annotations.
type serviceAccountRoleAnnotationObservedEdge struct {
	clusterPositiveEdgeBase
	roleARN string // WO-6: retained privately for explicit correlation.
}

// WO-6: NewServiceAccountRoleAnnotationObservedEdge requires a concrete positive annotation.
func NewServiceAccountRoleAnnotationObservedEdge(
	cluster, namespace, serviceAccount, roleARN string,
	observedAt time.Time,
) ClusterPositiveEdge {
	base, ok := newClusterPositiveEdgeBase(cluster, namespace, serviceAccount, observedAt)
	if !ok || roleARN == "" {
		return nil
	}
	return serviceAccountRoleAnnotationObservedEdge{clusterPositiveEdgeBase: base, roleARN: roleARN}
}

// WO-6: Report the sealed service-account annotation observation category.
func (serviceAccountRoleAnnotationObservedEdge) Type() ClusterPositiveEdgeType {
	return ServiceAccountRoleAnnotationObserved
}

// WO-6: Seal service-account annotation observations to this package.
func (serviceAccountRoleAnnotationObservedEdge) positiveClusterObservation() {}

// WO-6: MarshalJSON emits the sanitized artifact projection.
func (e serviceAccountRoleAnnotationObservedEdge) MarshalJSON() ([]byte, error) {
	return marshalClusterPositiveEdge(e.Type(), e.ObservedAt())
}

// ServiceAccountRoleAnnotationEvidence exposes the role only for a validated WO-6 annotation edge.
// WO-6: Keep raw role identity behind explicit in-process access.
func ServiceAccountRoleAnnotationEvidence(edge ClusterPositiveEdge) (string, bool) {
	typed, ok := edge.(serviceAccountRoleAnnotationObservedEdge)
	if !ok {
		return "", false
	}
	return typed.roleARN, true
}

// WO-6: workloadReferenceObservedEdge can represent only observed workload references.
type workloadReferenceObservedEdge struct {
	clusterPositiveEdgeBase
	workloadKind string // WO-6: retained privately for explicit correlation.
	workloadName string // WO-6: retained privately for explicit correlation.
}

// WO-6: NewWorkloadReferenceObservedEdge requires a concrete workload-to-SA reference.
func NewWorkloadReferenceObservedEdge(
	cluster, namespace, serviceAccount, workloadKind, workloadName string,
	observedAt time.Time,
) ClusterPositiveEdge {
	base, ok := newClusterPositiveEdgeBase(cluster, namespace, serviceAccount, observedAt)
	if !ok || workloadKind == "" || workloadName == "" {
		return nil
	}
	return workloadReferenceObservedEdge{
		clusterPositiveEdgeBase: base,
		workloadKind:            workloadKind,
		workloadName:            workloadName,
	}
}

// WO-6: Report the sealed workload reference observation category.
func (workloadReferenceObservedEdge) Type() ClusterPositiveEdgeType {
	return WorkloadReferenceObserved
}

// WO-6: Seal workload reference observations to this package.
func (workloadReferenceObservedEdge) positiveClusterObservation() {}

// WO-6: MarshalJSON emits the sanitized artifact projection.
func (e workloadReferenceObservedEdge) MarshalJSON() ([]byte, error) {
	return marshalClusterPositiveEdge(e.Type(), e.ObservedAt())
}

// WorkloadReferenceEvidence exposes workload identity only for a validated WO-6 reference edge.
// WO-6: Keep raw workload identity behind explicit in-process access.
func WorkloadReferenceEvidence(edge ClusterPositiveEdge) (string, string, bool) {
	typed, ok := edge.(workloadReferenceObservedEdge)
	if !ok {
		return "", "", false
	}
	return typed.workloadKind, typed.workloadName, true
}

// WO-6: podReferenceObservedEdge can represent only observed pod references.
type podReferenceObservedEdge struct {
	clusterPositiveEdgeBase
	podName string // WO-6: retained privately for explicit correlation.
}

// WO-6: NewPodReferenceObservedEdge requires a concrete pod-to-SA reference.
func NewPodReferenceObservedEdge(
	cluster, namespace, serviceAccount, podName string,
	observedAt time.Time,
) ClusterPositiveEdge {
	base, ok := newClusterPositiveEdgeBase(cluster, namespace, serviceAccount, observedAt)
	if !ok || podName == "" {
		return nil
	}
	return podReferenceObservedEdge{clusterPositiveEdgeBase: base, podName: podName}
}

// WO-6: Report the sealed pod reference observation category.
func (podReferenceObservedEdge) Type() ClusterPositiveEdgeType {
	return PodReferenceObserved
}

// WO-6: Seal pod reference observations to this package.
func (podReferenceObservedEdge) positiveClusterObservation() {}

// WO-6: MarshalJSON emits the sanitized artifact projection.
func (e podReferenceObservedEdge) MarshalJSON() ([]byte, error) {
	return marshalClusterPositiveEdge(e.Type(), e.ObservedAt())
}

// PodReferenceEvidence exposes pod identity only for a validated WO-6 reference edge.
// WO-6: Keep raw pod identity behind explicit in-process access.
func PodReferenceEvidence(edge ClusterPositiveEdge) (string, bool) {
	typed, ok := edge.(podReferenceObservedEdge)
	if !ok {
		return "", false
	}
	return typed.podName, true
}
