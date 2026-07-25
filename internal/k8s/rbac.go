package k8s

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
				findings = append(findings, Finding{
					ID:           FindingClusterAdminBinding,
					Severity:     SeverityCritical,
					ResourceType: "ClusterRoleBinding",
					ResourceID:   crb.Name,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("cluster-admin bound to %s %s/%s", subject.Kind, subject.Namespace, subject.Name),
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
			findings = append(findings, Finding{
				ID:           FindingWildcardRBAC,
				Severity:     SeverityCritical,
				ResourceType: "ClusterRole",
				ResourceID:   role.Name,
				Cluster:      cfg.Cluster,
				Message:      wildcardRuleMessage(role.Rules),
			})
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
			findings = append(findings, Finding{
				ID:           FindingWildcardRBAC,
				Severity:     SeverityCritical,
				ResourceType: "Role",
				ResourceID:   role.Name,
				Namespace:    role.Namespace,
				Cluster:      cfg.Cluster,
				Message:      wildcardRuleMessage(role.Rules),
			})
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
			findings = append(findings, Finding{
				ID:           FindingClusterAdminBinding,
				Severity:     SeverityCritical,
				ResourceType: "RoleBinding",
				ResourceID:   rb.Name,
				Namespace:    rb.Namespace,
				Cluster:      cfg.Cluster,
				Message:      fmt.Sprintf("%s ClusterRole bound to %s %s/%s", rb.RoleRef.Name, subject.Kind, subject.Namespace, subject.Name),
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

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}
