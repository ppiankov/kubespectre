package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNetworkPolicyScanner_MissingPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
	)

	scanner := &NetworkPolicyScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.ID != FindingMissingNetworkPolicy {
			t.Errorf("finding ID = %q, want %q", f.ID, FindingMissingNetworkPolicy)
		}
		if f.Severity != SeverityHigh {
			t.Errorf("severity = %q, want %q", f.Severity, SeverityHigh)
		}
	}
}

func TestNetworkPolicyScanner_WithPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "secure-ns"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "secure-ns"},
		},
	)

	scanner := &NetworkPolicyScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (namespace has policy)", len(findings))
	}
}

func TestNetworkPolicyScanner_SkipsKubeSystem(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-public"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-node-lease"}},
	)

	scanner := &NetworkPolicyScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (system namespaces skipped)", len(findings))
	}
}

func TestNetworkPolicyScanner_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app-b"}},
	)

	scanner := &NetworkPolicyScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", Namespace: "app-a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only app-a)", len(findings))
	}
	if findings[0].ResourceID != "app-a" {
		t.Errorf("resource ID = %q, want %q", findings[0].ResourceID, "app-a")
	}
}

func TestNetworkPolicyScanner_Mixed(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "secured"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unsecured"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-web", Namespace: "secured"},
		},
	)

	scanner := &NetworkPolicyScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ResourceID != "unsecured" {
		t.Errorf("resource ID = %q, want %q", findings[0].ResourceID, "unsecured")
	}
}
