package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ppiankov/kubespectre/internal/k8s"
)

func TestSARIFReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}

	if err := r.Generate(testData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	version, ok := sarif["version"].(string)
	if !ok || version != "2.1.0" {
		t.Errorf("version = %v, want %q", sarif["version"], "2.1.0")
	}

	schema, ok := sarif["$schema"].(string)
	if !ok || schema == "" {
		t.Error("missing $schema field")
	}

	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs count = %d, want 1", len(runs))
	}

	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) != 2 {
		t.Errorf("results count = %d, want 2", len(results))
	}

	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok || len(rules) != 14 {
		t.Errorf("rules count = %d, want 14", len(rules))
	}
}

func TestSARIFLevel(t *testing.T) {
	tests := []struct {
		sev  k8s.Severity
		want string
	}{
		{k8s.SeverityCritical, "error"},
		{k8s.SeverityHigh, "error"},
		{k8s.SeverityMedium, "warning"},
		{k8s.SeverityLow, "note"},
	}

	for _, tt := range tests {
		got := sarifLevel(tt.sev)
		if got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestBuildSARIFURI(t *testing.T) {
	tests := []struct {
		finding k8s.Finding
		want    string
	}{
		{
			k8s.Finding{Cluster: "prod", Namespace: "default", ResourceType: "Pod", ResourceID: "nginx"},
			"k8s://prod/default/Pod/nginx",
		},
		{
			k8s.Finding{Cluster: "prod", Namespace: "", ResourceType: "ClusterRoleBinding", ResourceID: "admin"},
			"k8s://prod/ClusterRoleBinding/admin",
		},
	}

	for _, tt := range tests {
		got := buildSARIFURI(tt.finding)
		if got != tt.want {
			t.Errorf("buildSARIFURI() = %q, want %q", got, tt.want)
		}
	}
}
