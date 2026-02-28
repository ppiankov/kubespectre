package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// ImageScanner audits container images for missing digest pinning
// and untrusted registries.
type ImageScanner struct{}

func (s *ImageScanner) Name() string { return "image" }

func (s *ImageScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 3
	return nil, nil
}
