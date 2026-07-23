package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuditLogScanner_MissingPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver-node1",
				Namespace: "kube-system",
				Labels:    map[string]string{"component": "kube-apiserver"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "kube-apiserver",
						Command: []string{"kube-apiserver", "--etcd-servers=https://127.0.0.1:2379"},
					},
				},
			},
		},
	)

	scanner := &AuditLogScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingMissingAuditPolicy {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingMissingAuditPolicy)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityHigh)
	}
}

func TestAuditLogScanner_WithPolicyInCommand(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver-node1",
				Namespace: "kube-system",
				Labels:    map[string]string{"component": "kube-apiserver"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "kube-apiserver",
						Command: []string{
							"kube-apiserver",
							"--audit-policy-file=/etc/kubernetes/audit-policy.yaml",
							"--audit-log-path=/var/log/audit.log",
						},
					},
				},
			},
		},
	)

	scanner := &AuditLogScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (audit policy configured)", len(findings))
	}
}

func TestAuditLogScanner_WithPolicyInArgs(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver-node1",
				Namespace: "kube-system",
				Labels:    map[string]string{"component": "kube-apiserver"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "kube-apiserver",
						Command: []string{"kube-apiserver"},
						Args:    []string{"--audit-policy-file=/etc/kubernetes/audit-policy.yaml"},
					},
				},
			},
		},
	)

	scanner := &AuditLogScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (audit policy in args)", len(findings))
	}
}

func TestAuditLogScanner_ManagedCluster(t *testing.T) {
	// No kube-apiserver pod visible (EKS, GKE, AKS)
	client := fake.NewSimpleClientset()

	scanner := &AuditLogScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("severity = %q, want %q (informational for managed clusters)", findings[0].Severity, SeverityLow)
	}
}

// WO-23: Exclude matching API-server pods without hiding neighboring evidence.
func TestAuditLogScanner_Exclusions(t *testing.T) {
	exclusions, err := NewExclusions(nil, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "skip", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver", "scan": "skip"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "kube-apiserver"}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "kube-apiserver"}}}},
	)

	findings, err := (&AuditLogScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", Exclusions: exclusions})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ResourceID != "keep" {
		t.Fatalf("findings = %#v, want only neighboring API server", findings)
	}
}

// WO-23: An excluded control-plane namespace cannot produce an absence inference.
func TestAuditLogScanner_ExcludedNamespaceSuppressesManagedInference(t *testing.T) {
	exclusions, err := NewExclusions([]string{"kube-system"}, nil)
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}

	findings, err := (&AuditLogScanner{}).Audit(
		context.Background(),
		fake.NewSimpleClientset(),
		AuditConfig{Cluster: "test", Exclusions: exclusions},
	)
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for excluded control-plane namespace", findings)
	}
}
