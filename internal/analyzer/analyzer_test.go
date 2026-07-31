package analyzer

import (
	"testing"

	"github.com/ppiankov/kubespectre/internal/k8s"
)

func TestAnalyze(t *testing.T) {
	result := &k8s.ScanResult{
		Findings: []k8s.Finding{
			{ID: k8s.FindingWildcardRBAC, Severity: k8s.SeverityCritical, ResourceType: "ClusterRoleBinding", Message: "wildcard"},
			{ID: k8s.FindingHostNetwork, Severity: k8s.SeverityHigh, ResourceType: "Pod", Message: "host network"},
			{ID: k8s.FindingDefaultServiceAccount, Severity: k8s.SeverityMedium, ResourceType: "ServiceAccount", Message: "default SA"},
			{ID: k8s.FindingNoImageDigest, Severity: k8s.SeverityLow, ResourceType: "Pod", Message: "no digest"},
		},
		ResourcesScanned: 42,
		Errors:           []string{"some warning"},
	}

	cfg := AnalyzerConfig{SeverityMin: k8s.SeverityMedium}
	ar := Analyze(result, cfg)

	if len(ar.Findings) != 3 {
		t.Errorf("got %d filtered findings, want 3", len(ar.Findings))
	}
	if ar.Summary.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", ar.Summary.TotalFindings)
	}
	if ar.Summary.TotalResourcesScanned != 42 {
		t.Errorf("TotalResourcesScanned = %d, want 42", ar.Summary.TotalResourcesScanned)
	}
	if ar.Summary.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", ar.Summary.BySeverity["critical"])
	}
	if ar.Summary.BySeverity["high"] != 1 {
		t.Errorf("BySeverity[high] = %d, want 1", ar.Summary.BySeverity["high"])
	}
	if ar.Summary.BySeverity["medium"] != 1 {
		t.Errorf("BySeverity[medium] = %d, want 1", ar.Summary.BySeverity["medium"])
	}
	if ar.Summary.ByResourceType["Pod"] != 1 {
		t.Errorf("ByResourceType[Pod] = %d, want 1", ar.Summary.ByResourceType["Pod"])
	}
	if ar.Summary.ByFindingID["WILDCARD_RBAC"] != 1 {
		t.Errorf("ByFindingID[WILDCARD_RBAC] = %d, want 1", ar.Summary.ByFindingID["WILDCARD_RBAC"])
	}
	if len(ar.Errors) != 1 {
		t.Errorf("got %d errors, want 1", len(ar.Errors))
	}
}

func TestAnalyzeNoFindings(t *testing.T) {
	result := &k8s.ScanResult{ResourcesScanned: 10}
	ar := Analyze(result, AnalyzerConfig{SeverityMin: k8s.SeverityLow})

	if len(ar.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(ar.Findings))
	}
	if ar.Summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", ar.Summary.TotalFindings)
	}
}

// WO-49: N identical context-deadline-exceeded errors from one auditor must
// collapse into one summarized message; a lone timeout error and any other
// error shape must pass through unchanged.
func TestAnalyze_CollapsesTimeoutErrorCascade(t *testing.T) {
	result := &k8s.ScanResult{
		Errors: []string{
			`service-account: list serviceaccounts in namespace "ns1": Get "...": context deadline exceeded`,
			`service-account: list serviceaccounts in namespace "ns2": Get "...": context deadline exceeded`,
			`service-account: list serviceaccounts in namespace "ns3": Get "...": context deadline exceeded`,
			`secret: list secrets: some other transient failure`,
			`pod-security: list pods: Get "...": context deadline exceeded`,
		},
	}

	ar := Analyze(result, AnalyzerConfig{SeverityMin: k8s.SeverityLow})

	if len(ar.Errors) != 3 {
		t.Fatalf("got %d errors, want 3 (3 service-account collapsed to 1, plus secret and pod-security unchanged): %v", len(ar.Errors), ar.Errors)
	}
	if ar.Errors[0] != "service-account: 3 calls failed with context deadline exceeded (increase --timeout for a cluster this size)" {
		t.Errorf("collapsed message = %q", ar.Errors[0])
	}
	if ar.Errors[1] != `secret: list secrets: some other transient failure` {
		t.Errorf("non-timeout error changed: %q", ar.Errors[1])
	}
	// A single (uncollapsed) timeout error keeps its original text.
	if ar.Errors[2] != `pod-security: list pods: Get "...": context deadline exceeded` {
		t.Errorf("lone timeout error changed: %q", ar.Errors[2])
	}
}

func TestAnalyzeFilterAll(t *testing.T) {
	result := &k8s.ScanResult{
		Findings: []k8s.Finding{
			{ID: k8s.FindingNoImageDigest, Severity: k8s.SeverityLow, Message: "no digest"},
			{ID: k8s.FindingDefaultServiceAccount, Severity: k8s.SeverityMedium, Message: "default SA"},
		},
		ResourcesScanned: 5,
	}

	ar := Analyze(result, AnalyzerConfig{SeverityMin: k8s.SeverityCritical})
	if len(ar.Findings) != 0 {
		t.Errorf("got %d findings, want 0 (all filtered out)", len(ar.Findings))
	}
}
