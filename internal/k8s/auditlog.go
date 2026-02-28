package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// AuditLogScanner checks for audit policy configuration.
type AuditLogScanner struct{}

func (s *AuditLogScanner) Name() string { return "audit-log" }

func (s *AuditLogScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 3
	return nil, nil
}
