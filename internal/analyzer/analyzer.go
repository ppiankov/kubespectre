package analyzer

import (
	"github.com/ppiankov/kubespectre/internal/k8s"
)

// Analyze filters findings by minimum severity and computes summary statistics.
func Analyze(result *k8s.ScanResult, cfg AnalyzerConfig) *AnalysisResult {
	var filtered []k8s.Finding
	for _, f := range result.Findings {
		if k8s.MeetsSeverityMin(f.Severity, cfg.SeverityMin) {
			filtered = append(filtered, f)
		}
	}

	summary := Summary{
		TotalResourcesScanned: result.ResourcesScanned,
		TotalFindings:         len(filtered),
		BySeverity:            make(map[string]int),
		ByResourceType:        make(map[string]int),
		ByFindingID:           make(map[string]int),
	}

	for _, f := range filtered {
		summary.BySeverity[string(f.Severity)]++
		summary.ByResourceType[f.ResourceType]++
		summary.ByFindingID[string(f.ID)]++
	}

	return &AnalysisResult{
		Findings: filtered,
		Summary:  summary,
		Errors:   result.Errors,
	}
}
