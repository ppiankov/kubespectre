package k8s

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WO-54: defaultSystemManagedRolePrefixes are ClusterRole/Role name prefixes
// recognized as cloud-platform-managed, used when
// AuditConfig.SystemManagedRolePrefixes is empty. This never suppresses
// WILDCARD_RBAC -- unlike isSystemRole below, which fully excludes findings
// for the built-in system:/cluster-admin/admin/edit/view roles -- it only
// adds metadata so an operator triaging output can separate platform-managed
// roles (not operator-actionable) from custom app roles at a glance.
var defaultSystemManagedRolePrefixes = []string{"eks:", "system:"}

// WO-54: rbacNarrowWildcardResources is a closed allowlist of resource lists
// so narrow that a wildcard verb on them alone poses minimal risk -- e.g.
// leader-election leases, the near-universal controller-runtime/kubebuilder
// scaffolding pattern seen in essentially every microservice using that
// framework. A rule combining one of these resources with any other resource
// is NOT matched, since the moment another resource is added the
// narrow-blast-radius assumption no longer holds.
var rbacNarrowWildcardResources = [][]string{
	{"leases"},
}

// WO-41: SubjectLiveness is a closed four-value enum recording whether a
// CLUSTER_ADMIN_BINDING subject's referenced object was confirmed to exist,
// confirmed absent, could not be checked at all (e.g. RBAC denial), or is
// structurally not checkable (User/Group are not first-class K8s API objects).
const (
	SubjectLivenessConfirmedExists = "confirmed_exists"
	SubjectLivenessConfirmedAbsent = "confirmed_absent"
	SubjectLivenessCheckFailed     = "check_failed"
	SubjectLivenessNotCheckable    = "not_checkable"
)

// RBACScanner audits RBAC bindings and roles for wildcard permissions and
// admin-equivalent bindings to non-system subjects, at both cluster scope
// (ClusterRole/ClusterRoleBinding) and namespace scope (Role/RoleBinding).
type RBACScanner struct{}

func (s *RBACScanner) Name() string { return "rbac" }

func (s *RBACScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	// WO-25: preserve the posture-only contract; discard the scanned-object count.
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-25: auditWithCount reports the RBAC objects examined.
// WO-32: coverage spans cluster-scoped ClusterRoles/ClusterRoleBindings AND
// namespaced Roles/RoleBindings so namespace-admin-equivalent misconfigurations
// are no longer invisible.
func (s *RBACScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding
	scanned := 0 // WO-33: count only RBAC objects that survive exclusion filtering.

	// Check ClusterRoleBindings for cluster-admin bound to non-system subjects
	bindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list cluster role bindings: %w", err)
	}

	for _, crb := range bindings.Items {
		// WO-23: Enforce label exclusions before producing binding findings.
		if cfg.Exclusions.Matches("", crb.Labels) {
			continue
		}
		scanned++ // WO-33: examined (not operator-excluded) cluster role binding.
		if crb.RoleRef.Name == "cluster-admin" {
			for _, subject := range crb.Subjects {
				if isSystemSubject(subject.Name, subject.Namespace) {
					continue
				}
				// WO-41: subject-liveness is additional context on this existing
				// finding, never a severity change -- see resolveSubjectLiveness.
				liveness := resolveSubjectLiveness(ctx, client, subject)
				findings = append(findings, Finding{
					ID:           FindingClusterAdminBinding,
					Severity:     SeverityCritical,
					ResourceType: "ClusterRoleBinding",
					ResourceID:   crb.Name,
					Cluster:      cfg.Cluster,
					Message:      clusterAdminBindingMessage(subject, liveness),
					Metadata:     map[string]any{"subject_kind": subject.Kind, "subject_liveness": liveness},
				})
			}
		}
	}

	// Check ClusterRoles for wildcard verbs or resources
	roles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list cluster roles: %w", err)
	}

	for _, role := range roles.Items {
		// WO-23: Enforce label exclusions before producing role findings.
		if cfg.Exclusions.Matches("", role.Labels) {
			continue
		}
		scanned++ // WO-33: examined (not operator-excluded) cluster role.
		if isSystemRole(role.Name) {
			continue
		}
		if ruleHasWildcard(role.Rules) {
			findings = append(findings, buildWildcardRBACFinding("ClusterRole", role.Name, "", cfg, role.Rules))
		}
	}

	// WO-32: Check namespaced Roles for wildcard verbs or resources.
	nsRoles, err := client.RbacV1().Roles(cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list roles: %w", err)
	}

	for _, role := range nsRoles.Items {
		// WO-32: mirror the ClusterRole path — honor exclusions and skip system roles.
		if cfg.Exclusions.Matches(role.Namespace, role.Labels) {
			continue
		}
		scanned++ // WO-33: examined (not operator-excluded) namespaced role.
		if isSystemRole(role.Name) {
			continue
		}
		if ruleHasWildcard(role.Rules) {
			findings = append(findings, buildWildcardRBACFinding("Role", role.Name, role.Namespace, cfg, role.Rules))
		}
	}

	// WO-32: Check namespaced RoleBindings that grant a non-system subject an
	// admin-equivalent ClusterRole (cluster-admin/admin/edit).
	roleBindings, err := client.RbacV1().RoleBindings(cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list role bindings: %w", err)
	}

	for _, rb := range roleBindings.Items {
		// WO-32: honor exclusions on the RoleBinding's own namespace/labels.
		if cfg.Exclusions.Matches(rb.Namespace, rb.Labels) {
			continue
		}
		scanned++ // WO-33: examined (not operator-excluded) role binding.
		if rb.RoleRef.Kind != "ClusterRole" || !isAdminEquivalentClusterRole(rb.RoleRef.Name) {
			continue
		}
		for _, subject := range rb.Subjects {
			if isSystemSubject(subject.Name, subject.Namespace) {
				continue
			}
			liveness := resolveSubjectLiveness(ctx, client, subject)
			findings = append(findings, Finding{
				ID:           FindingClusterAdminBinding,
				Severity:     SeverityCritical,
				ResourceType: "RoleBinding",
				ResourceID:   rb.Name,
				Namespace:    rb.Namespace,
				Cluster:      cfg.Cluster,
				Message:      roleBindingAdminMessage(rb.RoleRef.Name, subject, liveness),
				Metadata:     map[string]any{"subject_kind": subject.Kind, "subject_liveness": liveness},
			})
		}
	}

	// WO-33: report only RBAC objects examined post-exclusion across cluster and
	// namespace scope; with no exclusions this equals the total listed.
	return findings, scanned, nil
}

func isSystemSubject(name, namespace string) bool {
	if strings.HasPrefix(namespace, "kube-") {
		return true
	}
	systemNames := []string{
		"system:masters",
		"system:admin",
		"system:kube-controller-manager",
		"system:kube-scheduler",
		"system:node",
	}
	for _, sn := range systemNames {
		if name == sn {
			return true
		}
	}
	return strings.HasPrefix(name, "system:")
}

func isSystemRole(name string) bool {
	return strings.HasPrefix(name, "system:") || name == "cluster-admin" ||
		name == "admin" || name == "edit" || name == "view"
}

// WO-32: isAdminEquivalentClusterRole reports whether a ClusterRole name grants
// admin-equivalent access when bound (cluster-admin, admin, or edit).
func isAdminEquivalentClusterRole(name string) bool {
	return name == "cluster-admin" || name == "admin" || name == "edit"
}

// WO-32: ruleHasWildcard reports whether any rule grants a wildcard verb or
// resource, shared by the ClusterRole and namespaced Role checks.
func ruleHasWildcard(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
			return true
		}
	}
	return false
}

// WO-32: wildcardRuleMessage renders the first wildcard-bearing rule for a finding.
func wildcardRuleMessage(rules []rbacv1.PolicyRule) string {
	for _, rule := range rules {
		if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
			return fmt.Sprintf("wildcard permission: verbs=%v resources=%v", rule.Verbs, rule.Resources)
		}
	}
	return "wildcard permission"
}

// WO-54: buildWildcardRBACFinding shares the metadata/severity decision
// between the ClusterRole and namespaced Role wildcard checks. Neither
// condition ever suppresses the finding -- it always appears -- only the
// severity and metadata distinguish a likely-benign shape from the default.
func buildWildcardRBACFinding(resourceType, name, namespace string, cfg AuditConfig, rules []rbacv1.PolicyRule) Finding {
	severity := SeverityCritical
	var metadata map[string]any

	if isLikelySystemManagedRoleName(name, cfg.SystemManagedRolePrefixes) {
		metadata = map[string]any{"likely_system_managed": true}
	}
	if wildcardRulesAreAllNarrow(rules) {
		severity = SeverityLow
		if metadata == nil {
			metadata = map[string]any{}
		}
		metadata["narrow_wildcard_resource"] = true
	}

	return Finding{
		ID:           FindingWildcardRBAC,
		Severity:     severity,
		ResourceType: resourceType,
		ResourceID:   name,
		Namespace:    namespace,
		Cluster:      cfg.Cluster,
		Message:      wildcardRuleMessage(rules),
		Metadata:     metadata,
	}
}

// WO-54: isLikelySystemManagedRoleName reports whether name matches a
// recognized cloud-platform-managed prefix. Empty prefixes falls back to
// defaultSystemManagedRolePrefixes (eks:, system:).
func isLikelySystemManagedRoleName(name string, prefixes []string) bool {
	if len(prefixes) == 0 {
		prefixes = defaultSystemManagedRolePrefixes
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// WO-54: wildcardRulesAreAllNarrow reports whether every wildcard-triggering
// rule in rules matches the narrow-resource allowlist exactly. A role
// combining a narrow-resource wildcard rule with any broader wildcard rule
// returns false, so it stays at full severity.
func wildcardRulesAreAllNarrow(rules []rbacv1.PolicyRule) bool {
	sawWildcard := false
	for _, rule := range rules {
		if !containsWildcard(rule.Verbs) && !containsWildcard(rule.Resources) {
			continue
		}
		sawWildcard = true
		if !resourcesMatchNarrowAllowlist(rule.Resources) {
			return false
		}
	}
	return sawWildcard
}

// WO-54: resourcesMatchNarrowAllowlist reports whether resources is exactly
// (order-independent, no extras) one of rbacNarrowWildcardResources' entries.
func resourcesMatchNarrowAllowlist(resources []string) bool {
	for _, allowed := range rbacNarrowWildcardResources {
		if stringSetsEqual(resources, allowed) {
			return true
		}
	}
	return false
}

// WO-54: stringSetsEqual compares two string slices as sets (order-independent,
// duplicate-sensitive counts).
func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		counts[v]--
	}
	for _, c := range counts {
		if c != 0 {
			return false
		}
	}
	return true
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

// WO-41: resolveSubjectLiveness reports whether a CLUSTER_ADMIN_BINDING
// subject's referenced object was confirmed to exist right now. Only
// ServiceAccount is a first-class Kubernetes API object; User and Group are
// authentication-mechanism-asserted identities with no queryable object, so
// they are always reported not_checkable rather than silently skipped or
// defaulted to confirmed_exists.
func resolveSubjectLiveness(ctx context.Context, client kubernetes.Interface, subject rbacv1.Subject) string {
	if subject.Kind != "ServiceAccount" {
		return SubjectLivenessNotCheckable
	}
	if subject.Namespace == "" {
		// WO-41: an empty namespace means there is no reliable coordinate to
		// query -- never guess a namespace, which could resolve to the wrong object.
		return SubjectLivenessCheckFailed
	}
	_, err := client.CoreV1().ServiceAccounts(subject.Namespace).Get(ctx, subject.Name, metav1.GetOptions{})
	switch {
	case err == nil:
		return SubjectLivenessConfirmedExists
	case apierrors.IsNotFound(err):
		return SubjectLivenessConfirmedAbsent
	default:
		return SubjectLivenessCheckFailed
	}
}

// WO-41: clusterAdminBindingMessage adds a liveness-specific sentence only for
// the confirmed_absent case; every other outcome keeps today's message
// unchanged so existing consumers are not diluted with a no-op observation.
func clusterAdminBindingMessage(subject rbacv1.Subject, liveness string) string {
	base := fmt.Sprintf("cluster-admin bound to %s %s/%s", subject.Kind, subject.Namespace, subject.Name)
	if liveness == SubjectLivenessConfirmedAbsent {
		return base + " (subject not found -- namespace or ServiceAccount does not currently exist; safe to revoke immediately, nothing currently depends on it)"
	}
	return base
}

// WO-41: roleBindingAdminMessage mirrors clusterAdminBindingMessage for the
// namespaced RoleBinding admin-equivalent-grant finding.
func roleBindingAdminMessage(roleRefName string, subject rbacv1.Subject, liveness string) string {
	base := fmt.Sprintf("%s ClusterRole bound to %s %s/%s", roleRefName, subject.Kind, subject.Namespace, subject.Name)
	if liveness == SubjectLivenessConfirmedAbsent {
		return base + " (subject not found -- namespace or ServiceAccount does not currently exist; safe to revoke immediately, nothing currently depends on it)"
	}
	return base
}
