package analyzer

import (
	"fmt"
	"strings"

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
		// WO-49: collapse a cascade of per-namespace timeout errors from one
		// auditor into a single, actionable message instead of dozens of
		// near-identical raw error strings.
		Errors: collapseTimeoutErrors(result.Errors),
	}
}

// WO-49: timeoutErrorMarker is the exact substring context.DeadlineExceeded
// produces; used only to detect the cascade, never to fabricate a new
// error class.
const timeoutErrorMarker = "context deadline exceeded"

// WO-49: collapseTimeoutErrors groups repeated context-deadline-exceeded
// errors from the same auditor into one summarized message, so an operator
// sees "raise --timeout" once instead of dozens of identical lines. Any
// other error (including a lone timeout) passes through unchanged, in its
// original position.
func collapseTimeoutErrors(errs []string) []string {
	if len(errs) == 0 {
		return errs
	}

	counts := make(map[string]int)
	for _, e := range errs {
		if auditor, ok := timeoutAuditorPrefix(e); ok {
			counts[auditor]++
		}
	}

	emitted := make(map[string]bool)
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		auditor, ok := timeoutAuditorPrefix(e)
		if !ok {
			out = append(out, e)
			continue
		}
		if emitted[auditor] {
			continue
		}
		emitted[auditor] = true
		if counts[auditor] == 1 {
			out = append(out, e)
			continue
		}
		out = append(out, fmt.Sprintf(
			"%s: %d calls failed with context deadline exceeded (increase --timeout for a cluster this size)",
			auditor, counts[auditor],
		))
	}
	return out
}

// WO-49: timeoutAuditorPrefix extracts the leading "<auditor>: " prefix
// scanner.go's AuditAll attaches to every error, but only for errors that
// are actually a context-deadline-exceeded timeout -- any other error shape
// is left for passthrough.
func timeoutAuditorPrefix(e string) (string, bool) {
	if !strings.Contains(e, timeoutErrorMarker) {
		return "", false
	}
	idx := strings.Index(e, ": ")
	if idx < 0 {
		return "", false
	}
	return e[:idx], true
}
