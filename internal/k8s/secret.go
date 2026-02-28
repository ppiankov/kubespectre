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
	var findings []Finding

	ns := cfg.Namespace
	if ns == "" {
		ns = ""
	}

	secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	mountedSecrets := buildMountedSecretSet(pods.Items)

	staleDays := cfg.StaleDays
	if staleDays <= 0 {
		staleDays = 90
	}
	staleThreshold := time.Now().AddDate(0, 0, -staleDays)

	for _, secret := range secrets.Items {
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

	return findings, nil
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
