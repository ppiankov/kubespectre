package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// NetworkPolicyScanner audits namespaces for missing NetworkPolicy
// resources (default-allow-all).
type NetworkPolicyScanner struct{}

func (s *NetworkPolicyScanner) Name() string { return "network-policy" }

func (s *NetworkPolicyScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 2
	return nil, nil
}
