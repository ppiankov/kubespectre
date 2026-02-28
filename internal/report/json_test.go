package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	if err := r.Generate(testData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	schema, ok := envelope["$schema"].(string)
	if !ok || schema != "spectre/v1" {
		t.Errorf("$schema = %v, want %q", envelope["$schema"], "spectre/v1")
	}

	tool, ok := envelope["tool"].(string)
	if !ok || tool != "kubespectre" {
		t.Errorf("tool = %v, want %q", envelope["tool"], "kubespectre")
	}

	findings, ok := envelope["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Errorf("findings count = %d, want 2", len(findings))
	}
}

func TestJSONReporterNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	data := testData()
	data.Findings = nil

	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}
