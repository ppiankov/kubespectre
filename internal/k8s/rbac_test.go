package k8s

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRBACScanner_ClusterAdminBinding(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "dangerous-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deploy-bot", Namespace: "default"},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "system-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "system:masters", Namespace: ""},
			},
		},
	)

	scanner := &RBACScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingClusterAdminBinding {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingClusterAdminBinding)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityCritical)
	}
	if findings[0].ResourceID != "dangerous-binding" {
		t.Errorf("resource ID = %q, want %q", findings[0].ResourceID, "dangerous-binding")
	}
}

func TestRBACScanner_WildcardRole(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "overprivileged"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"pods"}, APIGroups: []string{""}},
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "wildcard-resources"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"get", "list"}, Resources: []string{"*"}, APIGroups: []string{""}},
			},
		},
		// System roles should be skipped
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "system:controller:whatever"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{""}},
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
			},
		},
	)

	scanner := &RBACScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.ID != FindingWildcardRBAC {
			t.Errorf("finding ID = %q, want %q", f.ID, FindingWildcardRBAC)
		}
	}
}

func TestRBACScanner_Clean(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "view"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "reader", Namespace: "monitoring"},
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "reader-role"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"get", "list"}, Resources: []string{"pods"}, APIGroups: []string{""}},
			},
		},
	)

	scanner := &RBACScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (clean cluster)", len(findings))
	}
}

func TestRBACScanner_SystemSubjectInKubeNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "coredns", Namespace: "kube-system"},
			},
		},
	)

	scanner := &RBACScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (kube-system SA should be skipped)", len(findings))
	}
}

// WO-23: Exclude labeled RBAC resources while retaining neighboring findings.
func TestRBACScanner_Exclusions(t *testing.T) {
	exclusions, err := NewExclusions(nil, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "skip-binding", Labels: map[string]string{"scan": "skip"}}, RoleRef: rbacv1.RoleRef{Name: "cluster-admin"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "keep-binding"}, RoleRef: rbacv1.RoleRef{Name: "cluster-admin"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "bob"}}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "skip-role", Labels: map[string]string{"scan": "skip"}}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"pods"}}}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "keep-role"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"pods"}}}},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", Exclusions: exclusions})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 2 || findings[0].ResourceID != "keep-binding" || findings[1].ResourceID != "keep-role" {
		t.Fatalf("findings = %#v, want neighboring binding and role", findings)
	}
}
