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

// WO-21: Exclude matching secrets without suppressing neighboring unused-secret findings.
func TestSecretScanner_Exclusions(t *testing.T) {
	exclusions, err := NewExclusions([]string{"excluded"}, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	recent := metav1.NewTime(time.Now())
	client := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "namespace-skip", Namespace: "excluded", CreationTimestamp: recent}, Type: corev1.SecretTypeOpaque},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "label-skip", Namespace: "default", Labels: map[string]string{"scan": "skip"}, CreationTimestamp: recent}, Type: corev1.SecretTypeOpaque},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "default", CreationTimestamp: recent}, Type: corev1.SecretTypeOpaque},
	)

	findings, err := (&SecretScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:    "test",
		StaleDays:  90,
		Exclusions: exclusions,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ResourceID != "keep" {
		t.Fatalf("findings = %#v, want only neighboring secret", findings)
	}
}

// WO-33: the scanned count must reflect only secrets that survive exclusion
// filtering, not every secret listed.
func TestSecretScanner_CountsOnlyEvaluatedSecrets(t *testing.T) {
	exclusions, err := NewExclusions([]string{"excluded"}, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	recent := metav1.NewTime(time.Now())
	client := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "namespace-skip", Namespace: "excluded", CreationTimestamp: recent}, Type: corev1.SecretTypeOpaque},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "label-skip", Namespace: "default", Labels: map[string]string{"scan": "skip"}, CreationTimestamp: recent}, Type: corev1.SecretTypeOpaque},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "default", CreationTimestamp: recent}, Type: corev1.SecretTypeOpaque},
	)

	_, scanned, err := (&SecretScanner{}).auditWithCount(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90, Exclusions: exclusions})
	if err != nil {
		t.Fatalf("auditWithCount() error = %v", err)
	}
	if scanned != 1 {
		t.Fatalf("scanned = %d, want 1 (only the evaluated secret, not the 3 listed)", scanned)
	}
}

// WO-34: a stale secret carrying a cert-manager.io/* or external-secrets.io/*
// annotation is down-ranked to medium; a plain stale secret stays high.
func TestSecretScanner_ManagedSecretDownranked(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cert-manager-webhook-ca", Namespace: "cert-manager", CreationTimestamp: staleTime,
				Annotations: map[string]string{"cert-manager.io/allow-direct-injection": "true"},
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "synced-secret", Namespace: "default", CreationTimestamp: staleTime,
				Annotations: map[string]string{"external-secrets.io/created-by": "controller"},
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "forgotten-secret", Namespace: "default", CreationTimestamp: staleTime},
			Type:       corev1.SecretTypeOpaque,
		},
		// Pods mounting all three so only STALE_SECRET (not UNUSED_SECRET_MOUNT) fires.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app1", Namespace: "cert-manager"}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes:    []corev1.Volume{{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "cert-manager-webhook-ca"}}}},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app2", Namespace: "default"}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes:    []corev1.Volume{{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "synced-secret"}}}},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app3", Namespace: "default"}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes:    []corev1.Volume{{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "forgotten-secret"}}}},
		}},
	)

	findings, err := (&SecretScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3 STALE_SECRET: %#v", len(findings), findings)
	}
	bySecret := map[string]Finding{}
	for _, f := range findings {
		bySecret[f.ResourceID] = f
	}
	if bySecret["cert-manager-webhook-ca"].Severity != SeverityMedium {
		t.Errorf("cert-manager-webhook-ca severity = %q, want medium", bySecret["cert-manager-webhook-ca"].Severity)
	}
	if bySecret["cert-manager-webhook-ca"].Metadata["managed"] != true {
		t.Errorf("cert-manager-webhook-ca metadata[managed] = %v, want true", bySecret["cert-manager-webhook-ca"].Metadata["managed"])
	}
	if bySecret["synced-secret"].Severity != SeverityMedium {
		t.Errorf("synced-secret severity = %q, want medium", bySecret["synced-secret"].Severity)
	}
	if bySecret["forgotten-secret"].Severity != SeverityHigh {
		t.Errorf("forgotten-secret severity = %q, want high (unaffected, no managed marker)", bySecret["forgotten-secret"].Severity)
	}
	if bySecret["forgotten-secret"].Metadata["managed"] != false {
		t.Errorf("forgotten-secret metadata[managed] = %v, want false", bySecret["forgotten-secret"].Metadata["managed"])
	}
}

// WO-34: DisableManagedSecretDownranking opts back into uniform severity.
func TestSecretScanner_ManagedSecretDownrankingDisabled(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cert-manager-webhook-ca", Namespace: "cert-manager", CreationTimestamp: staleTime,
				Annotations: map[string]string{"cert-manager.io/allow-direct-injection": "true"},
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app1", Namespace: "cert-manager"}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes:    []corev1.Volume{{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "cert-manager-webhook-ca"}}}},
		}},
	)

	findings, err := (&SecretScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:                         "test",
		StaleDays:                       90,
		DisableManagedSecretDownranking: true,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != SeverityHigh {
		t.Fatalf("findings = %#v, want 1 STALE_SECRET at high (downranking disabled)", findings)
	}
}

// WO-34: ManagedSecretMarkers overrides the built-in default marker list.
func TestSecretScanner_ManagedSecretMarkersConfigured(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "custom-managed", Namespace: "default", CreationTimestamp: staleTime,
				Annotations: map[string]string{"acme.internal/owner": "platform-team"},
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes:    []corev1.Volume{{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "custom-managed"}}}},
		}},
	)

	findings, err := (&SecretScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:              "test",
		StaleDays:            90,
		ManagedSecretMarkers: []string{"acme.internal/"},
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != SeverityMedium {
		t.Fatalf("findings = %#v, want 1 STALE_SECRET at medium (acme.internal/ configured)", findings)
	}
}
