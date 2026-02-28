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
