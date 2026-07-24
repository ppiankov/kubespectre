package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ppiankov/kubespectre/internal/k8s"
)

// WO-15: Build a report fixture containing sanitized cluster evidence.
func testDataWithClusterEvidence() Data {
	data := testData()
	observedAt := time.Date(2026, time.July, 23, 8, 9, 10, 0, time.UTC)
	data.ClusterPositiveEdges = []k8s.ClusterPositiveEdgeProjection{
		k8s.ProjectClusterPositiveEdge(
			k8s.NewServiceAccountRoleAnnotationObservedEdge(
				"private-cluster",
				"payments",
				"private-service-account",
				"private-role",
				observedAt,
			),
			false,
		),
	}
	data.NamespaceCoverage = []k8s.NamespaceCoverage{{
		Namespace:  "payments",
		State:      k8s.NamespaceCoverageComplete,
		ObservedAt: observedAt,
	}}
	return data
}

// WO-15: Verify report envelopes retain coverage without exposing raw edge identity.
func assertClusterEvidenceEnvelope(t *testing.T, envelope map[string]any) {
	t.Helper()
	edges, ok := envelope["cluster_positive_edges"].([]any)
	if !ok || len(edges) != 1 {
		t.Fatalf("cluster_positive_edges = %#v, want one", envelope["cluster_positive_edges"])
	}
	edge, ok := edges[0].(map[string]any)
	if !ok {
		t.Fatalf("edge = %#v, want object", edges[0])
	}
	if len(edge) != 2 || edge["type"] != "SERVICEACCOUNT_ROLE_ANNOTATION_OBSERVED" || edge["observed_at"] == nil {
		t.Errorf("edge projection = %#v, want sanitized type and observed_at only", edge)
	}

	coverage, ok := envelope["coverage"].([]any)
	if !ok || len(coverage) != 1 {
		t.Fatalf("coverage = %#v, want one namespace", envelope["coverage"])
	}
	namespace, ok := coverage[0].(map[string]any)
	if !ok || namespace["namespace"] != "payments" || namespace["state"] != "complete" {
		t.Errorf("coverage entry = %#v, want payments complete", coverage[0])
	}
}

// WO-15: Prove the JSON artifact carries positive cluster evidence end to end.
func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	if err := r.Generate(testDataWithClusterEvidence()); err != nil {
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
	assertClusterEvidenceEnvelope(t, envelope)
}

// WO-24: prove the join-key-enabled envelope carries full edge attribution.
func TestJSONReporterWithJoinKeys(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	data := testDataWithClusterEvidence()
	data.ClusterPositiveEdges = []k8s.ClusterPositiveEdgeProjection{
		k8s.ProjectClusterPositiveEdge(
			k8s.NewServiceAccountRoleAnnotationObservedEdge(
				"private-cluster",
				"payments",
				"private-service-account",
				"private-role",
				time.Date(2026, time.July, 23, 8, 9, 10, 0, time.UTC),
			),
			true,
		),
	}
	data.Config.IncludeClusterPositiveEdgeJoinKeys = true

	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	edges, ok := envelope["cluster_positive_edges"].([]any)
	if !ok || len(edges) != 1 {
		t.Fatalf("cluster_positive_edges = %#v, want one", envelope["cluster_positive_edges"])
	}
	edge, ok := edges[0].(map[string]any)
	if !ok {
		t.Fatalf("edge = %#v, want object", edges[0])
	}
	want := map[string]any{
		"type":            "SERVICEACCOUNT_ROLE_ANNOTATION_OBSERVED",
		"namespace":       "payments",
		"service_account": "private-service-account",
		"role_arn":        "private-role",
	}
	for key, expected := range want {
		got := edge[key]
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("cluster edge[%q] = %#v, want %#v", key, got, expected)
		}
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
