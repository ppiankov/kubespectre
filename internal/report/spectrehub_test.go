package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSpectreHubReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}

	if err := r.Generate(testData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	schema, ok := envelope["schema"].(string)
	if !ok || schema != "spectre/v1" {
		t.Errorf("schema = %v, want %q", envelope["schema"], "spectre/v1")
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

func TestSpectreHubSchemaField(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}
	if err := r.Generate(testData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// SpectreHub uses "schema" (not "$schema")
	if _, ok := raw["schema"]; !ok {
		t.Error("missing 'schema' field in SpectreHub output")
	}
	if _, ok := raw["$schema"]; ok {
		t.Error("SpectreHub output should use 'schema', not '$schema'")
	}
}
