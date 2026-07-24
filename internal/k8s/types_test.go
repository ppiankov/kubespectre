package k8s

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		got := SeverityRank(tt.sev)
		if got != tt.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestMeetsSeverityMin(t *testing.T) {
	tests := []struct {
		s, min Severity
		want   bool
	}{
		{SeverityCritical, SeverityLow, true},
		{SeverityCritical, SeverityCritical, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityLow, SeverityLow, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityMedium, SeverityMedium, true},
	}

	for _, tt := range tests {
		got := MeetsSeverityMin(tt.s, tt.min)
		if got != tt.want {
			t.Errorf("MeetsSeverityMin(%q, %q) = %v, want %v", tt.s, tt.min, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"critical", SeverityCritical},
		{"high", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"", SeverityLow},
		{"invalid", SeverityLow},
	}

	for _, tt := range tests {
		got := ParseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// WO-6: Lock the three ratified positive observation constructors.
func TestClusterPositiveEdgeConstructors(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	edges := []ClusterPositiveEdge{
		NewServiceAccountRoleAnnotationObservedEdge(
			"prod", "payments", "checkout", "arn:aws:iam::123456789012:role/checkout", observedAt,
		),
		NewWorkloadReferenceObservedEdge(
			"prod", "payments", "checkout", "Deployment", "checkout", observedAt,
		),
		NewPodReferenceObservedEdge("prod", "payments", "checkout", "checkout-abc", observedAt),
	}
	wantTypes := []ClusterPositiveEdgeType{
		ServiceAccountRoleAnnotationObserved,
		WorkloadReferenceObserved,
		PodReferenceObserved,
	}

	for i, edge := range edges {
		if edge == nil {
			t.Fatalf("edge %d is nil", i)
		}
		if edge.Type() != wantTypes[i] {
			t.Errorf("edge %d type = %q, want %q", i, edge.Type(), wantTypes[i])
		}
		if !edge.ObservedAt().Equal(observedAt) {
			t.Errorf("edge %d observed at = %s, want %s", i, edge.ObservedAt(), observedAt)
		}
	}
}

// WO-6: Prove incomplete evidence cannot construct an edge.
func TestClusterPositiveEdgeConstructorsRejectIncompleteEvidence(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	tests := []struct {
		name string
		edge ClusterPositiveEdge
	}{
		{"annotation without role", NewServiceAccountRoleAnnotationObservedEdge("prod", "ns", "sa", "", observedAt)},
		{"annotation without instant", NewServiceAccountRoleAnnotationObservedEdge("prod", "ns", "sa", "role", time.Time{})},
		{"workload without kind", NewWorkloadReferenceObservedEdge("prod", "ns", "sa", "", "name", observedAt)},
		{"workload without name", NewWorkloadReferenceObservedEdge("prod", "ns", "sa", "Deployment", "", observedAt)},
		{"pod without name", NewPodReferenceObservedEdge("prod", "ns", "sa", "", observedAt)},
		{"pod without service account", NewPodReferenceObservedEdge("prod", "ns", "", "pod", observedAt)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.edge != nil {
				t.Fatalf("edge = %#v, want nil", tt.edge)
			}
		})
	}
}

// WO-6: Prove edge JSON excludes raw identity and absence vocabulary.
func TestClusterPositiveEdgesDoNotSerializeIdentityOrAbsence(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	edge := NewServiceAccountRoleAnnotationObservedEdge(
		"prod", "secret-namespace", "secret-service-account", "secret-role-arn", observedAt,
	)

	encoded, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("marshal edge: %v", err)
	}
	got := string(encoded)
	for _, forbidden := range []string{
		"secret-namespace", "secret-service-account", "secret-role-arn",
		"negative", "absence", "orphan", "removable", "no_match",
	} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Errorf("serialized edge %s contains forbidden value %q", got, forbidden)
		}
	}
}

// WO-24: Project positive edge evidence into stable machine-readable shape.
func TestProjectClusterPositiveEdges(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	annotation := NewServiceAccountRoleAnnotationObservedEdge(
		"prod", "payments", "checkout-sa", "arn:aws:iam::123456789012:role/checkout", observedAt,
	)
	workload := NewWorkloadReferenceObservedEdge(
		"prod", "payments", "checkout-sa", "Deployment", "checkout", observedAt,
	)
	pod := NewPodReferenceObservedEdge("prod", "payments", "checkout-sa", "checkout-pod", observedAt)

	withoutJoinKeys := ProjectClusterPositiveEdges(
		[]ClusterPositiveEdge{annotation, workload, pod},
		false,
	)
	if len(withoutJoinKeys) != 3 {
		t.Fatalf("edges = %#v, want 3", withoutJoinKeys)
	}
	for _, edge := range withoutJoinKeys {
		if edge.ObservedAt != observedAt {
			t.Fatalf("ObservedAt = %v, want %v", edge.ObservedAt, observedAt)
		}
		if edge.Namespace != "" || edge.ServiceAccount != "" || edge.RoleARN != "" || edge.WorkloadKind != "" || edge.WorkloadName != "" || edge.PodName != "" {
			t.Fatalf("edge has join keys while disabled: %#v", edge)
		}
	}

	withJoinKeys := ProjectClusterPositiveEdges(
		[]ClusterPositiveEdge{annotation, workload, pod},
		true,
	)
	if got := withJoinKeys[0]; got.Namespace != "payments" || got.ServiceAccount != "checkout-sa" || got.RoleARN != "arn:aws:iam::123456789012:role/checkout" || got.WorkloadKind != "" || got.WorkloadName != "" || got.PodName != "" {
		t.Errorf("annotation projection = %#v", got)
	}
	if got := withJoinKeys[1]; got.WorkloadKind != "Deployment" || got.WorkloadName != "checkout" || got.PodName != "" {
		t.Errorf("workload projection = %#v", got)
	}
	if got := withJoinKeys[2]; got.PodName != "checkout-pod" {
		t.Errorf("pod projection = %#v", got)
	}

	if got := ProjectClusterPositiveEdge(nil, true); got != (ClusterPositiveEdgeProjection{}) {
		t.Fatalf("nil edge projection = %#v, want empty", got)
	}
}
