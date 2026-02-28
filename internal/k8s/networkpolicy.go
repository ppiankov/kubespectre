package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NetworkPolicyScanner audits namespaces for missing NetworkPolicy
// resources (default-allow-all).
type NetworkPolicyScanner struct{}

func (s *NetworkPolicyScanner) Name() string { return "network-policy" }

// skipNamespaces are namespaces excluded from network policy checks.
var skipNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

func (s *NetworkPolicyScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	var findings []Finding

	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		if skipNamespaces[ns.Name] {
			continue
		}
		if cfg.Namespace != "" && ns.Name != cfg.Namespace {
			continue
		}

		policies, err := client.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list network policies in %s: %w", ns.Name, err)
		}

		if len(policies.Items) == 0 {
			findings = append(findings, Finding{
				ID:           FindingMissingNetworkPolicy,
				Severity:     SeverityHigh,
				ResourceType: "Namespace",
				ResourceID:   ns.Name,
				Namespace:    ns.Name,
				Cluster:      cfg.Cluster,
				Message:      "namespace has no NetworkPolicy (default-allow-all)",
			})
		}
	}

	return findings, nil
}
