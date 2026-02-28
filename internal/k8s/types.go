package k8s

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

// ScanResult holds all findings from scanning a cluster.
type ScanResult struct {
	Findings         []Finding `json:"findings"`
	Errors           []string  `json:"errors,omitempty"`
	ResourcesScanned int       `json:"resources_scanned"`
}

// AuditConfig holds parameters that control auditing behavior.
type AuditConfig struct {
	Namespace         string
	StaleDays         int
	SeverityMin       Severity
	TrustedRegistries []string
	Cluster           string
}
