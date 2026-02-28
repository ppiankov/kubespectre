package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestImageScanner_NoDigest(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "nginx:latest"},
				},
			},
		},
	)

	scanner := &ImageScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingNoImageDigest {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingNoImageDigest)
	}
}

func TestImageScanner_WithDigest(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "nginx@sha256:abc123def456"},
				},
			},
		},
	)

	scanner := &ImageScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (image has digest)", len(findings))
	}
}

func TestImageScanner_UntrustedRegistry(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "evil.registry.io/malware@sha256:abc123"},
				},
			},
		},
	)

	scanner := &ImageScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{
		Cluster:           "test",
		TrustedRegistries: []string{"gcr.io/my-project"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingUntrustedRegistry {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingUntrustedRegistry)
	}
}

func TestImageScanner_TrustedRegistry(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "gcr.io/my-project/app@sha256:abc123"},
				},
			},
		},
	)

	scanner := &ImageScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{
		Cluster:           "test",
		TrustedRegistries: []string{"gcr.io/my-project"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (trusted + digest)", len(findings))
	}
}

func TestImageScanner_NoTrustedRegistriesConfigured(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "random.io/app@sha256:abc123"},
				},
			},
		},
	)

	scanner := &ImageScanner{}
	// No TrustedRegistries = skip untrusted registry check
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (no trusted registries configured)", len(findings))
	}
}

func TestImageScanner_InitContainers(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers:     []corev1.Container{{Name: "web", Image: "app@sha256:abc"}},
				InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.36"}},
			},
		},
	)

	scanner := &ImageScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (init container no digest)", len(findings))
	}
	if findings[0].Metadata["container"] != "init" {
		t.Errorf("container = %v, want %q", findings[0].Metadata["container"], "init")
	}
}

func TestImageScanner_BothViolations(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "evil.io/app:latest"},
				},
			},
		},
	)

	scanner := &ImageScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{
		Cluster:           "test",
		TrustedRegistries: []string{"gcr.io/safe"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No digest + untrusted registry = 2 findings
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
}

func TestHasDigest(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"nginx:latest", false},
		{"nginx", false},
		{"gcr.io/proj/app:v1", false},
		{"nginx@sha256:abc123", true},
		{"gcr.io/proj/app@sha256:abc123def", true},
	}
	for _, tt := range tests {
		got := hasDigest(tt.image)
		if got != tt.want {
			t.Errorf("hasDigest(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestIsTrustedRegistry(t *testing.T) {
	trusted := []string{"gcr.io/my-project", "docker.io"}
	tests := []struct {
		image string
		want  bool
	}{
		{"gcr.io/my-project/app:v1", true},
		{"gcr.io/other-project/app:v1", false},
		{"nginx:latest", true},         // Docker Hub shorthand, docker.io is trusted
		{"library/nginx:latest", true}, // Docker Hub library path
		{"evil.io/app:latest", false},
	}
	for _, tt := range tests {
		got := isTrustedRegistry(tt.image, trusted)
		if got != tt.want {
			t.Errorf("isTrustedRegistry(%q, %v) = %v, want %v", tt.image, trusted, got, tt.want)
		}
	}
}
