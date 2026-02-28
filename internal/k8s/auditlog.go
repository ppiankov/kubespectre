package k8s

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AuditLogScanner checks for audit policy configuration.
// It looks for the kube-apiserver pod in kube-system and verifies
// that --audit-policy-file is configured.
type AuditLogScanner struct{}

func (s *AuditLogScanner) Name() string { return "audit-log" }

func (s *AuditLogScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	var findings []Finding

	// Look for kube-apiserver pod in kube-system
	pods, err := client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return nil, fmt.Errorf("list kube-apiserver pods: %w", err)
	}

	if len(pods.Items) == 0 {
		// Managed cluster (EKS, GKE, AKS) — API server not visible as a pod.
		// We cannot verify audit policy, so report it as informational.
		findings = append(findings, Finding{
			ID:           FindingMissingAuditPolicy,
			Severity:     SeverityLow,
			ResourceType: "Cluster",
			ResourceID:   "kube-apiserver",
			Cluster:      cfg.Cluster,
			Message:      "kube-apiserver pod not found (managed cluster?); audit policy cannot be verified",
		})
		return findings, nil
	}

	for _, pod := range pods.Items {
		hasAuditPolicy := false
		for _, c := range pod.Spec.Containers {
			for _, arg := range c.Command {
				if strings.HasPrefix(arg, "--audit-policy-file") {
					hasAuditPolicy = true
					break
				}
			}
			if hasAuditPolicy {
				break
			}
			for _, arg := range c.Args {
				if strings.HasPrefix(arg, "--audit-policy-file") {
					hasAuditPolicy = true
					break
				}
			}
			if hasAuditPolicy {
				break
			}
		}

		if !hasAuditPolicy {
			findings = append(findings, Finding{
				ID:           FindingMissingAuditPolicy,
				Severity:     SeverityHigh,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "kube-apiserver does not have --audit-policy-file configured",
			})
		}
	}

	return findings, nil
}
