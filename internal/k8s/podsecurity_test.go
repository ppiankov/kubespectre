package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool { return &b }

func TestPodSecurityScanner_Privileged(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:            "app",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					},
				},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingPrivilegedContainer {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingPrivilegedContainer)
	}
}

func TestPodSecurityScanner_HostNetwork(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "net-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers:  []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingHostNetwork {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingHostNetwork)
	}
}

func TestPodSecurityScanner_HostPID(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pid-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostPID:    true,
				Containers: []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingHostPID {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingHostPID)
	}
}

func TestPodSecurityScanner_MultipleViolations(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				HostPID:     true,
				Containers: []corev1.Container{
					{
						Name:            "main",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:            "init",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					},
				},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// hostNetwork + hostPID + 2 privileged containers = 4
	if len(findings) != 4 {
		t.Errorf("got %d findings, want 4", len(findings))
	}
}

func TestPodSecurityScanner_Clean(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:            "app",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(false)},
					},
				},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestPodSecurityScanner_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "prod"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)}},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "other-pod", Namespace: "staging"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers:  []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", Namespace: "prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1 (only prod namespace)", len(findings))
	}
}

// WO-21: Exclude matching pods without suppressing neighboring violations.
func TestPodSecurityScanner_Exclusions(t *testing.T) {
	exclusions, err := NewExclusions([]string{"excluded"}, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "namespace-skip", Namespace: "excluded"}, Spec: corev1.PodSpec{HostNetwork: true}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "label-skip", Namespace: "default", Labels: map[string]string{"scan": "skip"}}, Spec: corev1.PodSpec{HostNetwork: true}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "default"}, Spec: corev1.PodSpec{HostNetwork: true}},
	)

	findings, err := (&PodSecurityScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:    "test",
		Exclusions: exclusions,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ResourceID != "keep" {
		t.Fatalf("findings = %#v, want only neighboring pod", findings)
	}
}
