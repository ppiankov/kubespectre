package k8s

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// PodSecurityScanner audits pods for privileged containers,
// hostNetwork, and hostPID violations.
type PodSecurityScanner struct{}

func (s *PodSecurityScanner) Name() string { return "pod-security" }

func (s *PodSecurityScanner) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	// Stub: real implementation in Session 2
	return nil, nil
}
