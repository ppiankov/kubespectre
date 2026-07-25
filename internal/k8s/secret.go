package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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

	secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list secrets: %w", err)
	}

	pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list pods: %w", err)
	}

	mountedSecrets := buildMountedSecretSet(pods.Items)

	staleDays := cfg.StaleDays
	if staleDays <= 0 {
		staleDays = 90
	}
	staleThreshold := time.Now().AddDate(0, 0, -staleDays)

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

		// Check staleness
		if secret.CreationTimestamp.Time.Before(staleThreshold) {
			findings = append(findings, Finding{
				ID:           FindingStaleSecret,
				Severity:     SeverityHigh,
				ResourceType: "Secret",
				ResourceID:   secret.Name,
				Namespace:    secret.Namespace,
				Cluster:      cfg.Cluster,
				Message:      fmt.Sprintf("secret created %d+ days ago (threshold: %d days)", staleDays, staleDays),
				Metadata:     map[string]any{"created": secret.CreationTimestamp.Format(time.RFC3339)},
			})
		}

		// Check if secret is mounted by any pod
		key := secret.Namespace + "/" + secret.Name
		if !mountedSecrets[key] {
			findings = append(findings, Finding{
				ID:           FindingUnusedSecretMount,
				Severity:     SeverityHigh,
				ResourceType: "Secret",
				ResourceID:   secret.Name,
				Namespace:    secret.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "secret is not mounted by any pod",
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
