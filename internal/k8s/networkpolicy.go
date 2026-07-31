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
	// WO-25: preserve the posture-only contract; discard the scanned-object count.
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-25: auditWithCount reports the namespaces examined for NetworkPolicy coverage.
func (s *NetworkPolicyScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding

	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list namespaces: %w", err)
	}

	// WO-30: count only namespaces actually evaluated, not every listed one, so
	// the scanned count excludes skipped, excluded, and out-of-scope namespaces.
	evaluated := 0
	for _, ns := range namespaces.Items {
		// WO-23: Enforce configured namespace and label boundaries before policy checks.
		if cfg.Exclusions.Matches(ns.Name, ns.Labels) {
			continue
		}
		if skipNamespaces[ns.Name] {
			continue
		}
		if cfg.Namespace != "" && ns.Name != cfg.Namespace {
			continue
		}
		evaluated++

		policies, err := client.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, 0, fmt.Errorf("list network policies in %s: %w", ns.Name, err)
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

		// WO-43: opt-in convention lint, reusing the already-fetched per-namespace
		// NetworkPolicy list (zero new API calls). Entirely decoupled from
		// MISSING_NETWORK_POLICY -- both may fire independently, since a
		// namespace can have zero policies (MISSING_NETWORK_POLICY) and a
		// namespace can have policies that still don't match the baseline shape.
		if cfg.CheckDefaultDenyBaseline {
			findings = append(findings, checkDefaultDenyBaseline(ns.Name, policies.Items, cfg.Cluster)...)
		}
	}

	// WO-30: report the namespaces actually evaluated for network isolation.
	return findings, evaluated, nil
}
