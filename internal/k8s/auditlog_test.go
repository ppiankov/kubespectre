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
