package report

import (
	"io"
	"time"

	"github.com/ppiankov/kubespectre/internal/analyzer"
	"github.com/ppiankov/kubespectre/internal/k8s"
)

// Reporter is the interface for output formatters.
type Reporter interface {
	Generate(data Data) error
}

// Data holds all information needed to generate a report.
// WO-15: Preserve sanitized cluster observations and their proven coverage in envelopes.
type Data struct {
	Tool                 string                              `json:"tool"`
	Version              string                              `json:"version"`
	Timestamp            time.Time                           `json:"timestamp"`
	Target               Target                              `json:"target"`
	Config               ReportConfig                        `json:"config"`
	Findings             []k8s.Finding                       `json:"findings"`
	Summary              analyzer.Summary                    `json:"summary"`
	Errors               []string                            `json:"errors,omitempty"`
	ClusterPositiveEdges []k8s.ClusterPositiveEdgeProjection `json:"cluster_positive_edges,omitempty"` // WO-24: publish stable join-key artifacts when explicitly enabled.
	NamespaceCoverage    []k8s.NamespaceCoverage             `json:"coverage,omitempty"`               // WO-15: preserve proven scope alongside observations.
}

// Target identifies what was audited.
type Target struct {
	Type    string `json:"type"`
	URIHash string `json:"uri_hash"`
}

// ReportConfig captures the audit configuration used.
type ReportConfig struct {
	Namespace   string `json:"namespace,omitempty"`
	StaleDays   int    `json:"stale_days"`
	SeverityMin string `json:"severity_min"`
	// WO-24: echo whether join keys were enabled so consumers can trust edge attribution.
	IncludeClusterPositiveEdgeJoinKeys bool `json:"include_cluster_positive_edge_join_keys"`
}

// TextReporter generates human-readable terminal output.
type TextReporter struct {
	Writer io.Writer
}

// JSONReporter generates spectre/v1 envelope JSON output.
type JSONReporter struct {
	Writer io.Writer
}

// SpectreHubReporter generates SpectreHub envelope JSON output.
type SpectreHubReporter struct {
	Writer io.Writer
}

// SARIFReporter generates SARIF v2.1.0 output.
type SARIFReporter struct {
	Writer io.Writer
}
