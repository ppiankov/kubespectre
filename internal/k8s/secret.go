package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// SecretScanner audits secrets for staleness and unused mounts.
type SecretScanner struct{}

func (s *SecretScanner) Name() string { return "secret" }

func (s *SecretScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 2
	return nil, nil
}
