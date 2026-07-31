package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WO-34: defaultManagedSecretMarkers are annotation-key prefixes recognized as
// controller-managed secret provenance, used when AuditConfig.ManagedSecretMarkers
// is empty. Age alone is not a risk signal for a secret a controller actively owns.
var defaultManagedSecretMarkers = []string{"cert-manager.io/", "external-secrets.io/"}

// SecretScanner audits secrets for staleness and unused mounts.
type SecretScanner struct{}

func (s *SecretScanner) Name() string { return "secret" }

func (s *SecretScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	// WO-25: preserve the posture-only contract; discard the scanned-object count.
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-25: auditWithCount reports the secrets examined for lifecycle posture.
func (s *SecretScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding

	ns := cfg.Namespace

	// WO-48: retry a transient network blip before giving up this auditor's
	// entire finding set for the run.
	secrets, err := retryTransient(ctx, func() (*corev1.SecretList, error) {
		return client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list secrets: %w", err)
	}

	// WO-48: same transient-retry treatment for the auxiliary pod-mount lookup.
	pods, err := retryTransient(ctx, func() (*corev1.PodList, error) {
		return client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list pods: %w", err)
	}

	mountedSecrets := buildMountedSecretSet(pods.Items)

	staleDays := cfg.StaleDays
	if staleDays <= 0 {
		staleDays = 90
	}
	staleThreshold := time.Now().AddDate(0, 0, -staleDays)

	managedMarkers := cfg.ManagedSecretMarkers
	if len(managedMarkers) == 0 {
		managedMarkers = defaultManagedSecretMarkers
	}

	scanned := 0 // WO-33: count only secrets that survive exclusion filtering.
	for _, secret := range secrets.Items {
		// WO-21: Enforce the operator boundary before producing secret findings.
		if cfg.Exclusions.Matches(secret.Namespace, secret.Labels) {
			continue
		}
		// WO-33: count secrets examined post-exclusion; the type/helm skips below
		// are finding heuristics, not exclusions, so those secrets still count.
		scanned++
		// Skip service account tokens and helm secrets
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			continue
		}
		if isHelmSecret(secret) {
			continue
		}

		// WO-34/WO-37: age and pod-mount absence alone do not indicate risk for a
		// secret a recognized controller actively owns (e.g. cert-manager,
		// external-secrets) -- such secrets are commonly consumed via Ingress
		// tls.secretName or webhook caBundle injection, never a pod mount. Both
		// checks below down-rank rather than silently drop the finding, unless
		// the operator has disabled this recognition.
		managed := !cfg.DisableManagedSecretDownranking && isManagedSecret(secret, managedMarkers)

		// Check staleness
		if secret.CreationTimestamp.Time.Before(staleThreshold) {
			severity := SeverityHigh
			message := fmt.Sprintf("secret created %d+ days ago (threshold: %d days)", staleDays, staleDays)
			if managed {
				severity = SeverityMedium
				message = fmt.Sprintf("secret created %d+ days ago (threshold: %d days); carries a recognized controller-managed marker, so age alone does not indicate an unrotated or forgotten credential", staleDays, staleDays)
			}
			findings = append(findings, Finding{
				ID:           FindingStaleSecret,
				Severity:     severity,
				ResourceType: "Secret",
				ResourceID:   secret.Name,
				Namespace:    secret.Namespace,
				Cluster:      cfg.Cluster,
				Message:      message,
				Metadata:     map[string]any{"created": secret.CreationTimestamp.Format(time.RFC3339), "managed": managed},
			})
		}

		// Check if secret is mounted by any pod
		key := secret.Namespace + "/" + secret.Name
		if !mountedSecrets[key] {
			severity := SeverityHigh
			message := "secret is not mounted by any pod"
			if managed {
				severity = SeverityMedium
				message = "secret is not mounted by any pod; carries a recognized controller-managed marker, so it may be consumed via a non-pod-mount path (e.g. Ingress TLS, webhook caBundle injection)"
			}
			findings = append(findings, Finding{
				ID:           FindingUnusedSecretMount,
				Severity:     severity,
				ResourceType: "Secret",
				ResourceID:   secret.Name,
				Namespace:    secret.Namespace,
				Cluster:      cfg.Cluster,
				Message:      message,
				Metadata:     map[string]any{"managed": managed},
			})
		}
	}

	// WO-33: report only secrets examined post-exclusion; pods remain auxiliary
	// mount context, not the scanned unit for this auditor.
	return findings, scanned, nil
}

func buildMountedSecretSet(pods []corev1.Pod) map[string]bool {
	mounted := make(map[string]bool)
	for _, pod := range pods {
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil {
				key := pod.Namespace + "/" + vol.Secret.SecretName
				mounted[key] = true
			}
		}
		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			for _, env := range c.EnvFrom {
				if env.SecretRef != nil {
					key := pod.Namespace + "/" + env.SecretRef.Name
					mounted[key] = true
				}
			}
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					key := pod.Namespace + "/" + env.ValueFrom.SecretKeyRef.Name
					mounted[key] = true
				}
			}
		}
	}
	return mounted
}

func isHelmSecret(secret corev1.Secret) bool {
	return secret.Type == "helm.sh/release.v1"
}

// WO-34: isManagedSecret reports whether any annotation key on the secret
// starts with a recognized controller-managed marker prefix.
func isManagedSecret(secret corev1.Secret, markers []string) bool {
	for key := range secret.Annotations {
		for _, marker := range markers {
			if strings.HasPrefix(key, marker) {
				return true
			}
		}
	}
	return false
}
