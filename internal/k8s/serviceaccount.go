package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// ServiceAccountScanner audits workloads using the default service account
// and automountServiceAccountToken.
type ServiceAccountScanner struct{}

func (s *ServiceAccountScanner) Name() string { return "service-account" }

func (s *ServiceAccountScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 3
	return nil, nil
}
