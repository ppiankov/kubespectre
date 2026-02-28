package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretScanner_StaleSecret(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "old-secret",
				Namespace:         "default",
				CreationTimestamp: staleTime,
			},
			Type: corev1.SecretTypeOpaque,
		},
		// Pod that mounts the secret (so we only get stale, not unused)
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
				Volumes: []corev1.Volume{
					{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "old-secret"}}},
				},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingStaleSecret {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingStaleSecret)
	}
}

func TestSecretScanner_UnusedSecret(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "unused-secret",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeOpaque,
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingUnusedSecretMount {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingUnusedSecretMount)
	}
}

func TestSecretScanner_SkipsServiceAccountTokens(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -200))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "sa-token",
				Namespace:         "default",
				CreationTimestamp: staleTime,
			},
			Type: corev1.SecretTypeServiceAccountToken,
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (SA tokens skipped)", len(findings))
	}
}

func TestSecretScanner_SkipsHelmSecrets(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -200))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "sh.helm.release.v1.myapp.v1",
				Namespace:         "default",
				CreationTimestamp: staleTime,
			},
			Type: "helm.sh/release.v1",
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (helm secrets skipped)", len(findings))
	}
}

func TestSecretScanner_MountedViaEnv(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "db-creds",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						Env: []corev1.EnvVar{
							{
								Name: "DB_PASS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
									},
								},
							},
						},
					},
				},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (secret used via env)", len(findings))
	}
}

func TestSecretScanner_MountedViaEnvFrom(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "config-secret",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						EnvFrom: []corev1.EnvFromSource{
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "config-secret"}}},
						},
					},
				},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (secret used via envFrom)", len(findings))
	}
}

func TestSecretScanner_DefaultStaleDays(t *testing.T) {
	// Secret created 80 days ago should NOT be stale with default 90 days
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -80))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "recent-secret",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
				Volumes: []corev1.Volume{
					{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "recent-secret"}}},
				},
			},
		},
	)

	scanner := &SecretScanner{}
	// StaleDays=0 should default to 90
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (80 days < 90 default)", len(findings))
	}
}
