package k8s

import (
	"encoding/json"
	"reflect"
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
		// WO-29: identity fields are unexported; read them in-package to confirm
		// the disabled path leaves every join key empty.
		if edge.namespace != "" || edge.serviceAccount != "" || edge.roleARN != "" || edge.workloadKind != "" || edge.workloadName != "" || edge.podName != "" {
			t.Fatalf("edge has join keys while disabled: %#v", edge)
		}
		if edge.includeJoinKeys {
			t.Fatalf("edge join-key gate open while disabled: %#v", edge)
		}
	}

	withJoinKeys := ProjectClusterPositiveEdges(
		[]ClusterPositiveEdge{annotation, workload, pod},
		true,
	)
	if got := withJoinKeys[0]; got.namespace != "payments" || got.serviceAccount != "checkout-sa" || got.roleARN != "arn:aws:iam::123456789012:role/checkout" || got.workloadKind != "" || got.workloadName != "" || got.podName != "" {
		t.Errorf("annotation projection = %#v", got)
	}
	if got := withJoinKeys[1]; got.workloadKind != "Deployment" || got.workloadName != "checkout" || got.podName != "" {
		t.Errorf("workload projection = %#v", got)
	}
	if got := withJoinKeys[2]; got.podName != "checkout-pod" {
		t.Errorf("pod projection = %#v", got)
	}

	if got := ProjectClusterPositiveEdge(nil, true); got != (ClusterPositiveEdgeProjection{}) {
		t.Fatalf("nil edge projection = %#v, want empty", got)
	}
}

// WO-29: identity join keys must remain unexported so no caller outside this
// package can populate them with a struct literal and bypass the gate. Only
// Type and ObservedAt may be exported. This is the structural guarantee the
// flag-only WO-24 design lost.
func TestClusterPositiveEdgeProjectionSealsIdentityFields(t *testing.T) {
	allowedExported := map[string]bool{"Type": true, "ObservedAt": true}
	projectionType := reflect.TypeOf(ClusterPositiveEdgeProjection{})
	for i := 0; i < projectionType.NumField(); i++ {
		field := projectionType.Field(i)
		if field.IsExported() && !allowedExported[field.Name] {
			t.Errorf("field %q is exported; identity join keys must stay unexported to preserve the join-key gate", field.Name)
		}
	}
}

// WO-29: a projection built the only way an external caller can (setting just
// the exported Type/ObservedAt) must serialize no identity, proving the gate
// cannot be bypassed by a direct struct literal.
func TestClusterPositiveEdgeProjectionLiteralCannotLeakIdentity(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	// Only Type and ObservedAt are settable outside package k8s.
	projection := ClusterPositiveEdgeProjection{
		Type:       ServiceAccountRoleAnnotationObserved,
		ObservedAt: observedAt,
	}

	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("marshal projection: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal projection: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("projection serialized %d keys, want 2 (type, observed_at): %s", len(decoded), encoded)
	}
	for _, identityKey := range []string{
		"namespace", "service_account", "role_arn", "workload_kind", "workload_name", "pod_name",
	} {
		if _, ok := decoded[identityKey]; ok {
			t.Errorf("externally built projection leaked identity key %q: %s", identityKey, encoded)
		}
	}
}

// WO-29: the constructor's join-key path must still emit full attribution so the
// opt-in WO-24 surface is unchanged for legitimate callers.
func TestClusterPositiveEdgeProjectionConstructorEmitsJoinKeys(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	edge := NewServiceAccountRoleAnnotationObservedEdge(
		"prod", "payments", "checkout-sa", "arn:aws:iam::123456789012:role/checkout", observedAt,
	)

	encoded, err := json.Marshal(ProjectClusterPositiveEdge(edge, true))
	if err != nil {
		t.Fatalf("marshal projection: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal projection: %v", err)
	}
	want := map[string]any{
		"type":            string(ServiceAccountRoleAnnotationObserved),
		"namespace":       "payments",
		"service_account": "checkout-sa",
		"role_arn":        "arn:aws:iam::123456789012:role/checkout",
	}
	for key, expected := range want {
		if decoded[key] != expected {
			t.Errorf("join-key projection[%q] = %#v, want %#v", key, decoded[key], expected)
		}
	}
	if _, ok := decoded["observed_at"]; !ok {
		t.Errorf("join-key projection missing observed_at: %s", encoded)
	}
}
