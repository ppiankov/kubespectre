package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestServiceAccountScanner_DefaultSA(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get FindingDefaultServiceAccount but NOT FindingAutomountToken
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingDefaultServiceAccount {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingDefaultServiceAccount)
	}
}

func TestServiceAccountScanner_AutomountToken(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "app-sa",
				AutomountServiceAccountToken: boolPtr(true),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingAutomountToken {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingAutomountToken)
	}
}

func TestServiceAccountScanner_AutomountDefaultTrue(t *testing.T) {
	// When AutomountServiceAccountToken is nil, it defaults to true
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName: "app-sa",
				Containers:         []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingAutomountToken {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingAutomountToken)
	}
}

func TestServiceAccountScanner_BothViolations(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(true),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (default SA + automount)", len(findings))
	}
}

func TestServiceAccountScanner_Clean(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "app-sa",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestServiceAccountScanner_EmptySANameDefaultsToDefault(t *testing.T) {
	// Empty ServiceAccountName should be treated as "default"
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "no-sa-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.ID == FindingDefaultServiceAccount {
			found = true
		}
	}
	if !found {
		t.Error("expected FindingDefaultServiceAccount for pod with empty SA name")
	}
}

func TestServiceAccountScanner_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "prod"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "staging"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", Namespace: "prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1 (only prod)", len(findings))
	}
}
