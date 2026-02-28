package k8s

import (
	"context"
	"errors"
	"testing"

	"k8s.io/client-go/kubernetes"
)

type stubAuditor struct {
	name     string
	findings []Finding
	err      error
}

func (s *stubAuditor) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	return s.findings, s.err
}

func (s *stubAuditor) Name() string { return s.name }

func TestMultiAuditorAuditAll(t *testing.T) {
	finding1 := Finding{ID: FindingWildcardRBAC, Severity: SeverityCritical, Message: "wildcard"}
	finding2 := Finding{ID: FindingHostNetwork, Severity: SeverityHigh, Message: "host network"}

	auditors := []Auditor{
		&stubAuditor{name: "rbac", findings: []Finding{finding1}},
		&stubAuditor{name: "pod", findings: []Finding{finding2}},
	}

	ma := NewMultiAuditor(nil, auditors, 2)
	result, err := ma.AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(result.Findings))
	}
	if len(result.Errors) != 0 {
		t.Errorf("got %d errors, want 0", len(result.Errors))
	}
}

func TestMultiAuditorAuditAllWithError(t *testing.T) {
	auditors := []Auditor{
		&stubAuditor{name: "ok", findings: []Finding{{ID: FindingStaleSecret, Severity: SeverityHigh}}},
		&stubAuditor{name: "fail", err: errors.New("connection refused")},
	}

	ma := NewMultiAuditor(nil, auditors, 2)
	result, err := ma.AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Errorf("got %d findings, want 1", len(result.Findings))
	}
	if len(result.Errors) != 1 {
		t.Errorf("got %d errors, want 1", len(result.Errors))
	}
}

func TestMultiAuditorDefaultConcurrency(t *testing.T) {
	ma := NewMultiAuditor(nil, nil, 0)
	if ma.concurrency != 4 {
		t.Errorf("got concurrency %d, want 4", ma.concurrency)
	}
}

func TestAllAuditors(t *testing.T) {
	auditors := AllAuditors()
	if len(auditors) != 7 {
		t.Errorf("got %d auditors, want 7", len(auditors))
	}
}

func TestRBACOnlyAuditors(t *testing.T) {
	auditors := RBACOnlyAuditors()
	if len(auditors) != 1 {
		t.Errorf("got %d auditors, want 1", len(auditors))
	}
	if auditors[0].Name() != "rbac" {
		t.Errorf("got auditor name %q, want %q", auditors[0].Name(), "rbac")
	}
}
