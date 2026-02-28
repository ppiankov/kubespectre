package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ServiceAccountScanner audits workloads using the default service account
// and automountServiceAccountToken.
type ServiceAccountScanner struct{}

func (s *ServiceAccountScanner) Name() string { return "service-account" }

func (s *ServiceAccountScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	var findings []Finding

	ns := cfg.Namespace

	pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	for _, pod := range pods.Items {
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}

		if saName == "default" {
			findings = append(findings, Finding{
				ID:           FindingDefaultServiceAccount,
				Severity:     SeverityMedium,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "pod uses the default service account",
			})
		}

		if shouldFlagAutomount(pod.Spec) {
			findings = append(findings, Finding{
				ID:           FindingAutomountToken,
				Severity:     SeverityMedium,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "pod has automountServiceAccountToken enabled",
			})
		}
	}

	return findings, nil
}

// shouldFlagAutomount returns true if the pod will automount a SA token.
// The pod-level field overrides the SA-level default. If the pod spec
// does not explicitly set it to false, the token is mounted.
func shouldFlagAutomount(spec corev1.PodSpec) bool {
	if spec.AutomountServiceAccountToken != nil {
		return *spec.AutomountServiceAccountToken
	}
	// Not explicitly set — defaults to true (token is mounted)
	return true
}
