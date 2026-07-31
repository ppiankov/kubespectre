package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

// WO-52: a secret with an old creationTimestamp but a recent managedFields
// time must NOT be flagged stale -- creationTimestamp alone never changes
// when a secret is updated in place (the normal pattern for most
// secret-managing controllers), so this is the load-bearing regression this
// WO fixes.
func TestSecretScanner_RecentManagedFieldsTimeNotFlaggedStale(t *testing.T) {
	oldTime := metav1.NewTime(time.Now().AddDate(-2, 0, 0))
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "actively-rotated",
				Namespace:         "default",
				CreationTimestamp: oldTime,
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "some-controller", Time: &recentTime},
				},
			},
			Type: corev1.SecretTypeOpaque,
		},
		// Pod that mounts the secret so only the staleness check is exercised.
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
				Volumes: []corev1.Volume{
					{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "actively-rotated"}}},
				},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (recent managedFields time means the secret is actively maintained, not stale): %#v", len(findings), findings)
	}
}

// WO-52: a secret with no managedFields entries falls back to
// creationTimestamp unchanged -- identical to pre-WO-52 behavior.
func TestSecretScanner_NoManagedFieldsFallsBackToCreationTimestamp(t *testing.T) {
	oldTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "no-managed-fields",
				Namespace:         "default",
				CreationTimestamp: oldTime,
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
				Volumes: []corev1.Volume{
					{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "no-managed-fields"}}},
				},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingStaleSecret {
		t.Fatalf("findings = %#v, want 1 STALE_SECRET (no managedFields, falls back to creationTimestamp)", findings)
	}
}

// WO-53: a manually created (non-managed-marker) TLS secret referenced only
// by an Ingress's spec.tls[].secretName must NOT produce UNUSED_SECRET_MOUNT
// -- previously this was the exact false-positive class this check had no
// mitigation for.
func TestSecretScanner_IngressReferencedTLSSecretNotFlaggedUnused(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "manual-tls",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeTLS,
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{{SecretName: "manual-tls"}},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (secret is Ingress-referenced, not genuinely unused): %#v", len(findings), findings)
	}
}

// WO-53: a TLS secret not referenced by any pod or Ingress still produces
// UNUSED_SECRET_MOUNT unchanged.
func TestSecretScanner_UnreferencedTLSSecretStillFlagged(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "orphan-tls",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeTLS,
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{{SecretName: "some-other-secret"}},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingUnusedSecretMount {
		t.Fatalf("findings = %#v, want 1 UNUSED_SECRET_MOUNT (not referenced by any pod or matching Ingress)", findings)
	}
}

// WO-53: an Ingress in a different namespace from the secret must not mark
// it consumed -- Ingress TLS references are namespace-scoped.
func TestSecretScanner_IngressInDifferentNamespaceDoesNotMarkSecretMounted(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cross-ns-tls",
				Namespace:         "default",
				CreationTimestamp: recentTime,
			},
			Type: corev1.SecretTypeTLS,
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "other-ns"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{{SecretName: "cross-ns-tls"}},
			},
		},
	)

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingUnusedSecretMount {
		t.Fatalf("findings = %#v, want 1 UNUSED_SECRET_MOUNT (Ingress in a different namespace must not count)", findings)
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

// WO-37: an unused secret carrying a recognized managed-secret marker is
// down-ranked to medium; an unmanaged unused secret stays high.
func TestSecretScanner_ManagedUnusedSecretDownranked(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "webhook-ca", Namespace: "cert-manager", CreationTimestamp: recentTime,
				Annotations: map[string]string{"cert-manager.io/allow-direct-injection": "true"},
			},
			Type: corev1.SecretTypeOpaque,
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "forgotten", Namespace: "default", CreationTimestamp: recentTime},
			Type:       corev1.SecretTypeOpaque,
		},
	)

	findings, err := (&SecretScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 UNUSED_SECRET_MOUNT: %#v", len(findings), findings)
	}
	bySecret := map[string]Finding{}
	for _, f := range findings {
		bySecret[f.ResourceID] = f
	}
	if bySecret["webhook-ca"].Severity != SeverityMedium {
		t.Errorf("webhook-ca severity = %q, want medium", bySecret["webhook-ca"].Severity)
	}
	if bySecret["webhook-ca"].Metadata["managed"] != true {
		t.Errorf("webhook-ca metadata[managed] = %v, want true", bySecret["webhook-ca"].Metadata["managed"])
	}
	if bySecret["forgotten"].Severity != SeverityHigh {
		t.Errorf("forgotten severity = %q, want high (unaffected, no managed marker)", bySecret["forgotten"].Severity)
	}
}

// WO-37: DisableManagedSecretDownranking (from WO-34) also suppresses the
// UNUSED_SECRET_MOUNT down-rank -- one shared switch for both finding types.
func TestSecretScanner_ManagedUnusedSecretDownrankingDisabled(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "webhook-ca", Namespace: "cert-manager", CreationTimestamp: recentTime,
				Annotations: map[string]string{"cert-manager.io/allow-direct-injection": "true"},
			},
			Type: corev1.SecretTypeOpaque,
		},
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
		t.Fatalf("findings = %#v, want 1 UNUSED_SECRET_MOUNT at high (downranking disabled)", findings)
	}
}

// WO-50: secretListPage builds a *corev1.SecretList carrying the given
// continuation token, for reactors simulating a paginated List response.
func secretListPage(names []string, continueToken string) *corev1.SecretList {
	list := &corev1.SecretList{ListMeta: metav1.ListMeta{Continue: continueToken}}
	for _, name := range names {
		list.Items = append(list.Items, corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}})
	}
	return list
}

// WO-50: listSecretsPaged must accumulate every item across all pages, in a
// cluster small enough to fit in a single page as well as one that spans
// several.
func TestListSecretsPaged_FetchesAllPages(t *testing.T) {
	client := fake.NewSimpleClientset()
	calls := 0
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		switch calls {
		case 1:
			return true, secretListPage([]string{"s1", "s2"}, "tok-2"), nil
		case 2:
			return true, secretListPage([]string{"s3", "s4"}, "tok-3"), nil
		case 3:
			return true, secretListPage([]string{"s5"}, ""), nil
		default:
			t.Fatalf("unexpected extra List call #%d", calls)
			return false, nil, nil
		}
	})

	result, err := listSecretsPaged(context.Background(), client, "")
	if err != nil {
		t.Fatalf("list secrets paged: %v", err)
	}
	if len(result.Items) != 5 {
		t.Fatalf("got %d secrets, want 5 across 3 pages", len(result.Items))
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3 (one per page)", calls)
	}
}

// WO-50: the load-bearing regression -- a transient failure on one page must
// only retry that page, not restart the whole list from page 1. If it
// restarted, page 1's items would be re-fetched and duplicated, and the call
// count would exceed what one retried page requires.
func TestListSecretsPaged_RetriesOnlyFailingPageNotWholeList(t *testing.T) {
	client := fake.NewSimpleClientset()
	calls := 0
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		switch calls {
		case 1:
			return true, secretListPage([]string{"s1", "s2"}, "tok-2"), nil
		case 2:
			// WO-50: page 2's first attempt fails transiently.
			return true, nil, errors.New("stream error when reading response body; INTERNAL_ERROR; received from peer")
		case 3:
			return true, secretListPage([]string{"s3", "s4"}, "tok-3"), nil
		case 4:
			return true, secretListPage([]string{"s5"}, ""), nil
		default:
			t.Fatalf("unexpected extra List call #%d -- retry must not restart from page 1", calls)
			return false, nil, nil
		}
	})

	result, err := listSecretsPaged(context.Background(), client, "")
	if err != nil {
		t.Fatalf("list secrets paged: %v", err)
	}
	if len(result.Items) != 5 {
		t.Fatalf("got %d secrets, want 5 (no duplication or loss across the retried page)", len(result.Items))
	}
	if calls != 4 {
		t.Fatalf("calls = %d, want 4 (3 pages + 1 retry of page 2, no whole-list restart)", calls)
	}
}

// WO-50: a permanent error on any page must still fail immediately, not retry.
func TestListSecretsPaged_PermanentErrorNotRetried(t *testing.T) {
	client := fake.NewSimpleClientset()
	calls := 0
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, nil, k8serrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", errors.New("denied"))
	})

	_, err := listSecretsPaged(context.Background(), client, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (non-transient error must not retry)", calls)
	}
}
