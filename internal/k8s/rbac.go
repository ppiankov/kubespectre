package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// RBACScanner audits RBAC ClusterRoleBindings for wildcard permissions
// and cluster-admin bindings to non-system service accounts.
type RBACScanner struct{}

func (s *RBACScanner) Name() string { return "rbac" }

func (s *RBACScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 2
	return nil, nil
}
