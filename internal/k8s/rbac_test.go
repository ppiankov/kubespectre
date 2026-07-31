package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

// WO-32: a namespaced Role with a wildcard verb or resource must be flagged
// with resource_type Role; a benign namespaced Role must not.
func TestRBACScanner_WildcardNamespacedRole(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "ns-admin", Namespace: "team-a"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "wildcard-resources", Namespace: "team-b"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"get", "list"}, Resources: []string{"*"}, APIGroups: []string{""}},
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "team-a"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"get", "list"}, Resources: []string{"pods"}, APIGroups: []string{""}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (two wildcard Roles, benign Role skipped)", len(findings))
	}
	for _, f := range findings {
		if f.ID != FindingWildcardRBAC {
			t.Errorf("finding ID = %q, want %q", f.ID, FindingWildcardRBAC)
		}
		if f.ResourceType != "Role" {
			t.Errorf("resource_type = %q, want Role", f.ResourceType)
		}
		if f.Namespace == "" {
			t.Errorf("finding %q missing namespace", f.ResourceID)
		}
	}
}

// WO-32: a namespaced RoleBinding granting a non-system subject an
// admin-equivalent ClusterRole must be flagged with resource_type RoleBinding;
// a RoleBinding to a benign ClusterRole or to a system subject must not.
func TestRBACScanner_RiskyNamespacedRoleBinding(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "grant-admin", Namespace: "team-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deploy-bot", Namespace: "team-a"}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "grant-edit-system", Namespace: "team-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "coredns", Namespace: "kube-system"}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "grant-view", Namespace: "team-a"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only the admin RoleBinding to a non-system subject)", len(findings))
	}
	if findings[0].ID != FindingClusterAdminBinding {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingClusterAdminBinding)
	}
	if findings[0].ResourceType != "RoleBinding" || findings[0].ResourceID != "grant-admin" {
		t.Errorf("finding = %#v, want RoleBinding grant-admin", findings[0])
	}
	if findings[0].Namespace != "team-a" {
		t.Errorf("namespace = %q, want team-a", findings[0].Namespace)
	}
}

// WO-32: the scanned count includes the namespaced Roles and RoleBindings, on
// top of the cluster-scoped ClusterRoles/ClusterRoleBindings.
func TestRBACScanner_CountsNamespacedObjects(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cr-1"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "crb-1"}, RoleRef: rbacv1.RoleRef{Name: "view"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "r-1", Namespace: "team-a"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "r-2", Namespace: "team-b"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rb-1", Namespace: "team-a"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"}},
	)

	_, scanned, err := (&RBACScanner{}).auditWithCount(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("auditWithCount() error = %v", err)
	}
	// 1 ClusterRole + 1 ClusterRoleBinding + 2 Roles + 1 RoleBinding = 5.
	if scanned != 5 {
		t.Fatalf("scanned = %d, want 5 (cluster + namespaced RBAC objects)", scanned)
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

// WO-33: the scanned count must reflect only RBAC objects that survive
// exclusion filtering, not every object listed.
func TestRBACScanner_CountsOnlyEvaluatedObjects(t *testing.T) {
	exclusions, err := NewExclusions(nil, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "skip-crb", Labels: map[string]string{"scan": "skip"}}, RoleRef: rbacv1.RoleRef{Name: "view"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "keep-crb"}, RoleRef: rbacv1.RoleRef{Name: "view"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "skip-cr", Labels: map[string]string{"scan": "skip"}}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "keep-cr"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "skip-role", Namespace: "team-a", Labels: map[string]string{"scan": "skip"}}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "keep-role", Namespace: "team-a"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "skip-rb", Namespace: "team-a", Labels: map[string]string{"scan": "skip"}}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "keep-rb", Namespace: "team-a"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"}},
	)

	_, scanned, err := (&RBACScanner{}).auditWithCount(context.Background(), client, AuditConfig{Cluster: "test", Exclusions: exclusions})
	if err != nil {
		t.Fatalf("auditWithCount() error = %v", err)
	}
	// Only the 4 "keep-*" objects are evaluated; the 4 "skip-*" objects are excluded.
	if scanned != 4 {
		t.Fatalf("scanned = %d, want 4 (only evaluated objects, not the 8 listed)", scanned)
	}
}

// WO-41: a ServiceAccount subject that exists in the cluster gets
// subject_liveness=confirmed_exists, and the message is unchanged from today's.
func TestRBACScanner_SubjectLivenessConfirmedExists(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "live-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deploy-bot", Namespace: "default"}},
		},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "deploy-bot", Namespace: "default"}},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (must never change with liveness)", f.Severity, SeverityCritical)
	}
	if f.Metadata["subject_kind"] != "ServiceAccount" || f.Metadata["subject_liveness"] != SubjectLivenessConfirmedExists {
		t.Errorf("metadata = %+v, want subject_kind=ServiceAccount subject_liveness=confirmed_exists", f.Metadata)
	}
	if f.Message != "cluster-admin bound to ServiceAccount default/deploy-bot" {
		t.Errorf("message = %q, want unchanged base message for confirmed_exists", f.Message)
	}
}

// WO-41: a ServiceAccount subject referenced but never created gets
// subject_liveness=confirmed_absent, severity stays critical, and the message
// gains the dangling-binding sentence.
func TestRBACScanner_SubjectLivenessConfirmedAbsent(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "dangling-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "admin-user", Namespace: "kubernetes-dashboard"}},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (dangling status must never down-rank severity)", f.Severity, SeverityCritical)
	}
	if f.Metadata["subject_liveness"] != SubjectLivenessConfirmedAbsent {
		t.Errorf("subject_liveness = %v, want confirmed_absent", f.Metadata["subject_liveness"])
	}
	if !strings.Contains(f.Message, "safe to revoke immediately") {
		t.Errorf("message = %q, want it to include the dangling-binding sentence", f.Message)
	}
}

// WO-41: User and Group subjects are structurally not checkable -- Kubernetes
// has no API for either -- and must be reported not_checkable, never omitted
// or defaulted to confirmed_exists.
func TestRBACScanner_SubjectLivenessNotCheckableForUserAndGroup(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "user-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "group-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "developers"}},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Metadata["subject_liveness"] != SubjectLivenessNotCheckable {
			t.Errorf("subject %v: subject_liveness = %v, want not_checkable", f.Metadata["subject_kind"], f.Metadata["subject_liveness"])
		}
	}
}

// WO-41: a non-404 Get error (RBAC denial, timeout, etc.) must report
// check_failed -- never confirmed_absent -- since absence was never proven.
func TestRBACScanner_SubjectLivenessCheckFailed(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "unreadable-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deploy-bot", Namespace: "default"}},
		},
	)
	client.PrependReactor("get", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Metadata["subject_liveness"] != SubjectLivenessCheckFailed {
		t.Errorf("subject_liveness = %v, want check_failed", f.Metadata["subject_liveness"])
	}
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityCritical)
	}
	if strings.Contains(f.Message, "safe to revoke") {
		t.Errorf("message = %q, must not claim dangling status on check_failed", f.Message)
	}
}

// WO-54: a cloud-managed system role (eks: prefix) must still be flagged --
// never suppressed -- but carries likely_system_managed metadata so an
// operator can distinguish it from a custom app role at a glance.
func TestRBACScanner_WildcardEKSSystemRoleAnnotatedNotSuppressed(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "eks:addon-manager"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"list", "watch"}, Resources: []string{"*"}, APIGroups: []string{""}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (system-managed roles must still be flagged, not suppressed)", len(findings))
	}
	f := findings[0]
	if f.Metadata["likely_system_managed"] != true {
		t.Errorf("metadata = %#v, want likely_system_managed=true", f.Metadata)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (system-managed annotation does not change severity)", f.Severity, SeverityCritical)
	}
}

// WO-54: a custom app role with the same wildcard shape as a system role
// must NOT be marked likely_system_managed.
func TestRBACScanner_WildcardCustomRoleNotMarkedSystemManaged(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "talala-admin-role"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Metadata["likely_system_managed"] == true {
		t.Errorf("custom app role incorrectly marked likely_system_managed: %#v", findings[0].Metadata)
	}
}

// WO-54: SystemManagedRolePrefixes config overrides the default eks:/system: list.
func TestRBACScanner_WildcardCustomSystemManagedPrefixConfigured(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "acme-platform:controller"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:                   "test",
		SystemManagedRolePrefixes: []string{"acme-platform:"},
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Metadata["likely_system_managed"] != true {
		t.Fatalf("findings = %#v, want 1 marked likely_system_managed via configured prefix", findings)
	}
}

// WO-54: a rule whose resources are exactly [leases] is down-ranked to low
// severity and annotated, since leader-election leases pose minimal risk --
// this is the near-universal controller-runtime scaffolding pattern.
func TestRBACScanner_WildcardLeasesOnlyDownranked(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "wallet-go"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"leases"}, APIGroups: []string{"coordination.k8s.io"}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityLow {
		t.Errorf("severity = %q, want %q (leases-only wildcard)", f.Severity, SeverityLow)
	}
	if f.Metadata["narrow_wildcard_resource"] != true {
		t.Errorf("metadata = %#v, want narrow_wildcard_resource=true", f.Metadata)
	}
}

// WO-54: a role combining a leases-only wildcard rule with a broader
// wildcard rule must stay at full severity -- the narrow-resource allowlist
// covers ONLY a rule whose resources are leases and nothing else.
func TestRBACScanner_WildcardLeasesPlusBroaderRuleStaysFullSeverity(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "mixed-role"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"leases"}, APIGroups: []string{"coordination.k8s.io"}},
				{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (broader rule present, must not downrank)", f.Severity, SeverityCritical)
	}
	if f.Metadata["narrow_wildcard_resource"] == true {
		t.Errorf("metadata = %#v, must not mark narrow_wildcard_resource when a broader rule is also present", f.Metadata)
	}
}

// WO-54: a rule granting leases plus another resource (not leases-only) must
// NOT be down-ranked -- only an exact, narrow leases-only grant qualifies.
func TestRBACScanner_WildcardLeasesPlusOtherResourceInSameRuleNotDownranked(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "leases-and-configmaps"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"leases", "configmaps"}, APIGroups: []string{"coordination.k8s.io", ""}},
			},
		},
	)

	findings, err := (&RBACScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (leases+configmaps is not the narrow leases-only shape)", findings[0].Severity, SeverityCritical)
	}
}
