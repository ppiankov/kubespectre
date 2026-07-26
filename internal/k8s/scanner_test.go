package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

type stubAuditor struct {
	name     string
	findings []Finding
	err      error
}

// WO-6: Exercise the private evidence-auditor merge path independently.
type stubEvidenceAuditor struct {
	stubAuditor
	result      *serviceAccountEvidenceResult
	evidenceErr error
}

func (s *stubAuditor) Audit(_ context.Context, _ kubernetes.Interface, _ AuditConfig) ([]Finding, error) {
	return s.findings, s.err
}

func (s *stubAuditor) Name() string { return s.name }

// WO-6: Return controlled evidence-plane results for merge regression tests.
func (s *stubEvidenceAuditor) auditWithEvidence(
	context.Context,
	kubernetes.Interface,
	AuditConfig,
) (*serviceAccountEvidenceResult, error) {
	return s.result, s.evidenceErr
}

// WO-25: stubCountingAuditor reports a fixed scanned-object count for the
// aggregation regression tests.
type stubCountingAuditor struct {
	stubAuditor
	scanned int
}

// WO-25: return the controlled findings and scanned count for AuditAll.
func (s *stubCountingAuditor) auditWithCount(
	context.Context,
	kubernetes.Interface,
	AuditConfig,
) ([]Finding, int, error) {
	return s.findings, s.scanned, s.err
}

// WO-25: AuditAll must sum every auditor's scanned-object count into the result
// so total_resources_scanned is no longer pinned at zero. Auditors that do not
// report a count (legacy Audit-only) contribute zero rather than breaking.
func TestMultiAuditorAccumulatesResourcesScanned(t *testing.T) {
	auditors := []Auditor{
		&stubCountingAuditor{stubAuditor: stubAuditor{name: "rbac", findings: []Finding{{ID: FindingWildcardRBAC}}}, scanned: 12},
		&stubCountingAuditor{stubAuditor: stubAuditor{name: "pods", findings: []Finding{{ID: FindingHostNetwork}}}, scanned: 30},
		&stubAuditor{name: "legacy", findings: []Finding{{ID: FindingStaleSecret}}},
	}

	result, err := NewMultiAuditor(nil, auditors, 3).AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if result.ResourcesScanned != 42 {
		t.Fatalf("ResourcesScanned = %d, want 42 (12+30+0)", result.ResourcesScanned)
	}
}

// WO-25: a failed counting auditor records its error and contributes zero to the
// scanned total without suppressing the counts of healthy auditors.
func TestMultiAuditorFailedCountingAuditorContributesZero(t *testing.T) {
	auditors := []Auditor{
		&stubCountingAuditor{stubAuditor: stubAuditor{name: "ok", findings: []Finding{{ID: FindingWildcardRBAC}}}, scanned: 7},
		&stubCountingAuditor{stubAuditor: stubAuditor{name: "fail", err: errors.New("connection refused")}, scanned: 99},
	}

	result, err := NewMultiAuditor(nil, auditors, 2).AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if result.ResourcesScanned != 7 {
		t.Fatalf("ResourcesScanned = %d, want 7 (failed auditor adds nothing)", result.ResourcesScanned)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %#v, want one", result.Errors)
	}
}

// WO-25: real auditors report the objects they enumerate through AuditAll, so a
// run that scans resources reports a nonzero total. PodSecurity and Image both
// enumerate pods, so two pods yield four scanned units (once per auditor).
func TestMultiAuditorRealAuditorsReportNonzeroResourcesScanned(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app-a", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "nginx:latest"}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app-b", Namespace: "prod"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "nginx:latest"}}},
		},
	)

	result, err := NewMultiAuditor(client, []Auditor{&PodSecurityScanner{}, &ImageScanner{}}, 2).AuditAll(
		context.Background(),
		AuditConfig{Cluster: "test"},
	)
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if result.ResourcesScanned == 0 {
		t.Fatal("ResourcesScanned = 0, want nonzero after scanning pods")
	}
	if result.ResourcesScanned != 4 {
		t.Fatalf("ResourcesScanned = %d, want 4 (2 pods x PodSecurity+Image)", result.ResourcesScanned)
	}
}

func TestMultiAuditorAuditAll(t *testing.T) {
	finding1 := Finding{ID: FindingWildcardRBAC, Severity: SeverityCritical, Message: "wildcard"}
	finding2 := Finding{ID: FindingHostNetwork, Severity: SeverityHigh, Message: "host network"}

	auditors := []Auditor{
		&stubAuditor{name: "rbac", findings: []Finding{finding1}},
		&stubAuditor{name: "pod", findings: []Finding{finding2}},
	}

	ma := NewMultiAuditor(nil, auditors, 2)
	result, err := ma.AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(result.Findings))
	}
	if len(result.Errors) != 0 {
		t.Errorf("got %d errors, want 0", len(result.Errors))
	}
}

func TestMultiAuditorAuditAllWithError(t *testing.T) {
	auditors := []Auditor{
		&stubAuditor{name: "ok", findings: []Finding{{ID: FindingStaleSecret, Severity: SeverityHigh}}},
		&stubAuditor{name: "fail", err: errors.New("connection refused")},
	}

	ma := NewMultiAuditor(nil, auditors, 2)
	result, err := ma.AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Errorf("got %d findings, want 1", len(result.Findings))
	}
	if len(result.Errors) != 1 {
		t.Errorf("got %d errors, want 1", len(result.Errors))
	}
}

// WO-6: Keep partial evidence collection errors visible after the merge.
func TestMultiAuditorMergesEvidenceErrors(t *testing.T) {
	auditor := &stubEvidenceAuditor{
		stubAuditor: stubAuditor{name: "evidence"},
		result: &serviceAccountEvidenceResult{
			Findings: []Finding{{ID: FindingAutomountToken}},
			Errors:   []string{"partial workload collection"},
		},
	}

	result, err := NewMultiAuditor(nil, []Auditor{auditor}, 1).AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one", result.Findings)
	}
	if len(result.Errors) != 1 || result.Errors[0] != "evidence: partial workload collection" {
		t.Fatalf("errors = %#v, want prefixed evidence error", result.Errors)
	}
}

// WO-6: Keep fatal evidence collection errors visible without aborting peer auditors.
func TestMultiAuditorRecordsFatalEvidenceError(t *testing.T) {
	auditor := &stubEvidenceAuditor{
		stubAuditor: stubAuditor{name: "evidence"},
		evidenceErr: errors.New("pod collection failed"),
	}

	result, err := NewMultiAuditor(nil, []Auditor{auditor}, 1).AuditAll(context.Background(), AuditConfig{})
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if len(result.Errors) != 1 || result.Errors[0] != "evidence: pod collection failed" {
		t.Fatalf("errors = %#v, want prefixed fatal evidence error", result.Errors)
	}
}

func TestMultiAuditorDefaultConcurrency(t *testing.T) {
	ma := NewMultiAuditor(nil, nil, 0)
	if ma.concurrency != 4 {
		t.Errorf("got concurrency %d, want 4", ma.concurrency)
	}
}

func TestAllAuditors(t *testing.T) {
	// WO-40: bumped from 7 to 8 with the PersistentVolume auditor.
	auditors := AllAuditors()
	if len(auditors) != 8 {
		t.Errorf("got %d auditors, want 8", len(auditors))
	}
}

func TestRBACOnlyAuditors(t *testing.T) {
	auditors := RBACOnlyAuditors()
	if len(auditors) != 1 {
		t.Errorf("got %d auditors, want 1", len(auditors))
	}
	if auditors[0].Name() != "rbac" {
		t.Errorf("got auditor name %q, want %q", auditors[0].Name(), "rbac")
	}
}

// WO-6: Prove positive edges and coverage survive the full AuditAll path.
func TestMultiAuditorMergesPositiveEdgesAndCoverage(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 3, 4, 5, 0, time.UTC)
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "checkout-private",
				Namespace:   "payments",
				Annotations: map[string]string{serviceAccountRoleARNAnnotation: "role-private"},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-pod-private", Namespace: "payments"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "checkout-private",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)
	allowServiceAccountList(client, true)
	auditor := &ServiceAccountScanner{now: func() time.Time { return observedAt }}

	result, err := NewMultiAuditor(client, []Auditor{auditor}, 1).AuditAll(
		context.Background(),
		AuditConfig{Cluster: "prod"},
	)
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if len(result.ClusterPositiveEdges) != 2 {
		t.Fatalf("positive edges = %#v, want annotation and pod", result.ClusterPositiveEdges)
	}
	if len(result.NamespaceCoverage) != 1 || result.NamespaceCoverage[0].State != NamespaceCoverageComplete {
		t.Fatalf("coverage = %#v, want one complete namespace", result.NamespaceCoverage)
	}
	// WO-25: the evidence-path auditor reports its scanned pod through the summary.
	if result.ResourcesScanned != 1 {
		t.Fatalf("ResourcesScanned = %d, want 1 (single scanned pod)", result.ResourcesScanned)
	}
	for i, edge := range result.ClusterPositiveEdges {
		if !edge.ObservedAt().Equal(observedAt) {
			t.Errorf("edge %d observed at = %s, want %s", i, edge.ObservedAt(), observedAt)
		}
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	got := string(encoded)
	for _, required := range []string{"cluster_positive_edges", "SERVICEACCOUNT_ROLE_ANNOTATION_OBSERVED", observedAt.Format(time.RFC3339), `"state":"complete"`} {
		if !strings.Contains(got, required) {
			t.Errorf("serialized result %s lacks %q", got, required)
		}
	}
	for _, forbidden := range []string{
		"checkout-private", "checkout-pod-private", "role-private",
		"negative", "absence", "orphan", "removable", "no_match",
	} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Errorf("serialized result %s contains forbidden value %q", got, forbidden)
		}
	}
}

// WO-6: Prove unknown namespace coverage never yields a positive edge.
func TestMultiAuditorUnknownCoverageHasNoPositiveEdges(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "checkout",
				Namespace:   "payments",
				Annotations: map[string]string{serviceAccountRoleARNAnnotation: "role"},
			},
		},
	)
	allowServiceAccountList(client, false)

	result, err := NewMultiAuditor(client, []Auditor{&ServiceAccountScanner{}}, 1).AuditAll(
		context.Background(),
		AuditConfig{Cluster: "prod"},
	)
	if err != nil {
		t.Fatalf("audit all: %v", err)
	}
	if len(result.ClusterPositiveEdges) != 0 {
		t.Errorf("positive edges = %#v, want none", result.ClusterPositiveEdges)
	}
	if len(result.NamespaceCoverage) != 1 || result.NamespaceCoverage[0].State != NamespaceCoverageUnknown {
		t.Fatalf("coverage = %#v, want one unknown namespace", result.NamespaceCoverage)
	}
}
