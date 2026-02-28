package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/kubespectre/internal/analyzer"
	"github.com/ppiankov/kubespectre/internal/k8s"
)

func testData() Data {
	return Data{
		Tool:      "kubespectre",
		Version:   "0.1.0",
		Timestamp: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		Target:    Target{Type: "kubernetes-cluster", URIHash: "abc123"},
		Config:    ReportConfig{StaleDays: 90, SeverityMin: "low"},
		Findings: []k8s.Finding{
			{
				ID:           k8s.FindingWildcardRBAC,
				Severity:     k8s.SeverityCritical,
				ResourceType: "ClusterRoleBinding",
				ResourceID:   "admin-binding",
				Namespace:    "",
				Cluster:      "prod",
				Message:      "Wildcard verb on all resources",
			},
			{
				ID:           k8s.FindingHostNetwork,
				Severity:     k8s.SeverityHigh,
				ResourceType: "Pod",
				ResourceID:   "debug-pod",
				Namespace:    "default",
				Cluster:      "prod",
				Message:      "Pod uses host network",
			},
		},
		Summary: analyzer.Summary{
			TotalResourcesScanned: 100,
			TotalFindings:         2,
			BySeverity:            map[string]int{"critical": 1, "high": 1},
			ByResourceType:        map[string]int{"ClusterRoleBinding": 1, "Pod": 1},
			ByFindingID:           map[string]int{"WILDCARD_RBAC": 1, "HOST_NETWORK": 1},
		},
	}
}

func TestTextReporterWithFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	if err := r.Generate(testData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "kubespectre") {
		t.Error("output missing tool name")
	}
	if !strings.Contains(output, "Found 2 security issues") {
		t.Error("output missing findings count")
	}
	if !strings.Contains(output, "WILDCARD_RBAC") {
		t.Error("output missing finding ID")
	}
	if !strings.Contains(output, "admin-binding") {
		t.Error("output missing resource ID")
	}
	if !strings.Contains(output, "(cluster)") {
		t.Error("output missing cluster-scoped marker")
	}
	if !strings.Contains(output, "default") {
		t.Error("output missing namespace")
	}
	if !strings.Contains(output, "Resources scanned:  100") {
		t.Error("output missing summary")
	}
}

func TestTextReporterNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	data := testData()
	data.Findings = nil
	data.Summary.TotalFindings = 0
	data.Summary.BySeverity = map[string]int{}
	data.Summary.ByResourceType = map[string]int{}

	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No security issues found") {
		t.Error("output missing no-findings message")
	}
}

func TestTextReporterWithErrors(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	data := testData()
	data.Errors = []string{"rbac: connection refused"}

	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Warnings (1)") {
		t.Error("output missing warnings section")
	}
	if !strings.Contains(output, "connection refused") {
		t.Error("output missing error detail")
	}
}
