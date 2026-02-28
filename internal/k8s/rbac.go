package k8s

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RBACScanner audits RBAC ClusterRoleBindings for wildcard permissions
// and cluster-admin bindings to non-system service accounts.
type RBACScanner struct{}

func (s *RBACScanner) Name() string { return "rbac" }

func (s *RBACScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	var findings []Finding

	// Check ClusterRoleBindings for cluster-admin bound to non-system subjects
	bindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list cluster role bindings: %w", err)
	}

	for _, crb := range bindings.Items {
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
		return nil, fmt.Errorf("list cluster roles: %w", err)
	}

	for _, role := range roles.Items {
		if isSystemRole(role.Name) {
			continue
		}
		for _, rule := range role.Rules {
			if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
				findings = append(findings, Finding{
					ID:           FindingWildcardRBAC,
					Severity:     SeverityCritical,
					ResourceType: "ClusterRole",
					ResourceID:   role.Name,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("wildcard permission: verbs=%v resources=%v", rule.Verbs, rule.Resources),
				})
				break
			}
		}
	}

	return findings, nil
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

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}
