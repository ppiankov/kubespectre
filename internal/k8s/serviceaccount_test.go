package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestServiceAccountScanner_DefaultSA(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get FindingDefaultServiceAccount but NOT FindingAutomountToken
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingDefaultServiceAccount {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingDefaultServiceAccount)
	}
}

func TestServiceAccountScanner_AutomountToken(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "app-sa",
				AutomountServiceAccountToken: boolPtr(true),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingAutomountToken {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingAutomountToken)
	}
}

func TestServiceAccountScanner_AutomountDefaultTrue(t *testing.T) {
	// When AutomountServiceAccountToken is nil, it defaults to true
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName: "app-sa",
				Containers:         []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingAutomountToken {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingAutomountToken)
	}
}

func TestServiceAccountScanner_BothViolations(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(true),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (default SA + automount)", len(findings))
	}
}

func TestServiceAccountScanner_Clean(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "app-sa",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestServiceAccountScanner_EmptySANameDefaultsToDefault(t *testing.T) {
	// Empty ServiceAccountName should be treated as "default"
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "no-sa-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.ID == FindingDefaultServiceAccount {
			found = true
		}
	}
	if !found {
		t.Error("expected FindingDefaultServiceAccount for pod with empty SA name")
	}
}

func TestServiceAccountScanner_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "prod"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "staging"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &ServiceAccountScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", Namespace: "prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1 (only prod)", len(findings))
	}
}

// WO-6: Keep missing-client handling defensive after extracting pod collection.
func TestServiceAccountScannerNilClientReturnsError(t *testing.T) {
	_, err := (&ServiceAccountScanner{}).Audit(context.Background(), nil, AuditConfig{})
	if !errors.Is(err, errCoverageClientUnavailable) {
		t.Fatalf("error = %v, want unavailable client", err)
	}
}

// WO-6: Preserve the original pod-list error identity for direct callers.
func TestServiceAccountScannerPreservesPodListError(t *testing.T) {
	client := fake.NewSimpleClientset()
	wantErr := errors.New("pod API unavailable")
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})

	_, err := (&ServiceAccountScanner{}).Audit(context.Background(), client, AuditConfig{})
	if err != wantErr {
		t.Fatalf("error = %v, want original error %v", err, wantErr)
	}
}

// WO-6: Prove a covered namespace yields annotation, workload, and pod observations.
func TestServiceAccountScannerCollectsPositiveEdgesInProvenNamespace(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 2, 3, 4, 0, time.UTC)
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout",
				Namespace: "payments",
				Annotations: map[string]string{
					serviceAccountRoleARNAnnotation: "arn:aws:iam::123456789012:role/checkout",
				},
			},
		},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "payments"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "checkout"}},
					Spec: corev1.PodSpec{
						ServiceAccountName:           "checkout",
						AutomountServiceAccountToken: boolPtr(false),
						Containers:                   []corev1.Container{{Name: "app"}},
					},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-pod", Namespace: "payments"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "checkout",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)
	allowServiceAccountList(client, true)
	scanner := &ServiceAccountScanner{now: func() time.Time { return observedAt }}

	result, err := scanner.auditWithEvidence(context.Background(), client, AuditConfig{Cluster: "prod"})
	if err != nil {
		t.Fatalf("audit with evidence: %v", err)
	}
	if len(result.ClusterPositiveEdges) != 3 {
		t.Fatalf("positive edges = %#v, want annotation, workload, and pod", result.ClusterPositiveEdges)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].State != NamespaceCoverageComplete {
		t.Fatalf("coverage = %#v, want one complete namespace", result.Coverage)
	}

	wantTypes := []ClusterPositiveEdgeType{
		ServiceAccountRoleAnnotationObserved,
		WorkloadReferenceObserved,
		PodReferenceObserved,
	}
	for i, edge := range result.ClusterPositiveEdges {
		if edge.Type() != wantTypes[i] {
			t.Errorf("edge %d type = %q, want %q", i, edge.Type(), wantTypes[i])
		}
		if !edge.ObservedAt().Equal(observedAt) {
			t.Errorf("edge %d observed at = %s, want %s", i, edge.ObservedAt(), observedAt)
		}
	}
	if roleARN, ok := ServiceAccountRoleAnnotationEvidence(result.ClusterPositiveEdges[0]); !ok || roleARN == "" {
		t.Errorf("annotation evidence = %q, %v", roleARN, ok)
	}
	if kind, name, ok := WorkloadReferenceEvidence(result.ClusterPositiveEdges[1]); !ok || kind != "Deployment" || name != "checkout" {
		t.Errorf("workload evidence = %q/%q, %v", kind, name, ok)
	}
	if name, ok := PodReferenceEvidence(result.ClusterPositiveEdges[2]); !ok || name != "checkout-pod" {
		t.Errorf("pod evidence = %q, %v", name, ok)
	}
}

// WO-6: Prove unknown coverage suppresses every positive edge category.
func TestServiceAccountScannerUnknownCoverageEmitsNoEdges(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "checkout",
				Namespace:   "payments",
				Annotations: map[string]string{serviceAccountRoleARNAnnotation: "role"},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-pod", Namespace: "payments"},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "checkout",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		},
	)
	allowServiceAccountList(client, false)
	scanner := &ServiceAccountScanner{}

	result, err := scanner.auditWithEvidence(context.Background(), client, AuditConfig{Cluster: "prod"})
	if err != nil {
		t.Fatalf("audit with evidence: %v", err)
	}
	if len(result.ClusterPositiveEdges) != 0 {
		t.Errorf("positive edges = %#v, want none", result.ClusterPositiveEdges)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].State != NamespaceCoverageUnknown {
		t.Fatalf("coverage = %#v, want one unknown namespace", result.Coverage)
	}
}

// WO-6: Prove failed enumeration downgrades permitted scope to unknown.
func TestServiceAccountScannerEnumerationFailureDowngradesCoverage(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
	)
	allowServiceAccountList(client, true)
	wantErr := errors.New("serviceaccount API unavailable")
	client.PrependReactor("list", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})

	result, err := (&ServiceAccountScanner{}).auditWithEvidence(
		context.Background(),
		client,
		AuditConfig{Cluster: "prod"},
	)
	if err != nil {
		t.Fatalf("audit with evidence: %v", err)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].State != NamespaceCoverageUnknown {
		t.Fatalf("coverage = %#v, want one unknown namespace", result.Coverage)
	}
	if len(result.ClusterPositiveEdges) != 0 {
		t.Errorf("positive edges = %#v, want none", result.ClusterPositiveEdges)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], wantErr.Error()) {
		t.Fatalf("collection errors = %#v, want observable serviceaccount failure", result.Errors)
	}
}

// WO-6: Cover every supported workload reference with deterministic ordering.
func TestServiceAccountScannerCollectsAllWorkloadKindsInStableOrder(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 5, 6, 7, 0, time.UTC)
	podTemplate := corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		ServiceAccountName: "runtime-sa",
		Containers:         []corev1.Container{{Name: "app"}},
	}}
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "runtime"}}
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy", Namespace: "payments"},
			Spec:       appsv1.DeploymentSpec{Selector: selector, Template: podTemplate},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "stateful", Namespace: "payments"},
			Spec:       appsv1.StatefulSetSpec{Selector: selector, Template: podTemplate},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "payments"},
			Spec:       appsv1.DaemonSetSpec{Selector: selector, Template: podTemplate},
		},
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "payments"},
			Spec:       batchv1.JobSpec{Template: podTemplate},
		},
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "cron", Namespace: "payments"},
			Spec: batchv1.CronJobSpec{
				Schedule:    "0 * * * *",
				JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: podTemplate}},
			},
		},
	)
	allowServiceAccountList(client, true)
	scanner := &ServiceAccountScanner{now: func() time.Time { return observedAt }}

	result, err := scanner.auditWithEvidence(context.Background(), client, AuditConfig{Cluster: "prod"})
	if err != nil {
		t.Fatalf("audit with evidence: %v", err)
	}
	if len(result.ClusterPositiveEdges) != 5 {
		t.Fatalf("positive edges = %#v, want five workload edges", result.ClusterPositiveEdges)
	}
	want := []struct {
		kind string
		name string
	}{
		{kind: "CronJob", name: "cron"},
		{kind: "DaemonSet", name: "daemon"},
		{kind: "Deployment", name: "deploy"},
		{kind: "Job", name: "job"},
		{kind: "StatefulSet", name: "stateful"},
	}
	for i, edge := range result.ClusterPositiveEdges {
		kind, name, ok := WorkloadReferenceEvidence(edge)
		if !ok || kind != want[i].kind || name != want[i].name {
			t.Errorf("edge %d evidence = %q/%q, %v; want %q/%q", i, kind, name, ok, want[i].kind, want[i].name)
		}
		if edge.ServiceAccount() != "runtime-sa" || !edge.ObservedAt().Equal(observedAt) {
			t.Errorf("edge %d identity/time = %q/%s, want runtime-sa/%s", i, edge.ServiceAccount(), edge.ObservedAt(), observedAt)
		}
	}

	encoded, err := json.Marshal(result.ClusterPositiveEdges)
	if err != nil {
		t.Fatalf("marshal workload edges: %v", err)
	}
	for _, privateValue := range []string{"prod", "payments", "runtime-sa", "cron", "daemon", "deploy", "job", "stateful"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Errorf("serialized edges expose private value %q: %s", privateValue, encoded)
		}
	}
}

// WO-22: Enforce exclusions across findings, coverage, and every positive edge source.
func TestServiceAccountScannerAppliesExclusionsToEvidence(t *testing.T) {
	exclusions, err := NewExclusions([]string{"excluded"}, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "excluded"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kept"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "skip-sa", Namespace: "kept", Labels: map[string]string{"scan": "skip"}, Annotations: map[string]string{serviceAccountRoleARNAnnotation: "skip-role"}}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "keep-sa", Namespace: "kept", Annotations: map[string]string{serviceAccountRoleARNAnnotation: "keep-role"}}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "skip-workload", Namespace: "kept", Labels: map[string]string{"scan": "skip"}}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{}, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "skip-sa"}}}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "keep-workload", Namespace: "kept"}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{}, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "keep-sa"}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "namespace-skip", Namespace: "excluded"}, Spec: corev1.PodSpec{ServiceAccountName: "default", AutomountServiceAccountToken: boolPtr(false)}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "label-skip", Namespace: "kept", Labels: map[string]string{"scan": "skip"}}, Spec: corev1.PodSpec{ServiceAccountName: "default", AutomountServiceAccountToken: boolPtr(false)}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "keep-pod", Namespace: "kept"}, Spec: corev1.PodSpec{ServiceAccountName: "keep-sa", AutomountServiceAccountToken: boolPtr(false)}},
	)
	allowServiceAccountList(client, true)

	result, err := (&ServiceAccountScanner{}).auditWithEvidence(context.Background(), client, AuditConfig{
		Cluster:    "prod",
		Exclusions: exclusions,
	})
	if err != nil {
		t.Fatalf("auditWithEvidence() error = %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %#v, want excluded violating pods suppressed", result.Findings)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].Namespace != "kept" {
		t.Fatalf("coverage = %#v, want only kept namespace", result.Coverage)
	}
	if len(result.ClusterPositiveEdges) != 3 {
		t.Fatalf("edges = %#v, want kept annotation, workload, and pod", result.ClusterPositiveEdges)
	}
	for _, edge := range result.ClusterPositiveEdges {
		if edge.Namespace() != "kept" || strings.Contains(edge.ServiceAccount(), "skip") {
			t.Fatalf("excluded identity survived: %#v", edge)
		}
	}
}

// WO-26: Pin that an excluded namespace yields neither positive cluster edges
// nor a coverage entry — it is absent from the artifact, not marked "excluded".
// A "kept" namespace with an identical shape acts as the control proving the
// fixture would otherwise emit all three edge kinds and a coverage entry.
func TestServiceAccountScannerExcludedNamespaceHasNoEdgesOrCoverage(t *testing.T) {
	observedAt := time.Date(2026, time.July, 23, 6, 7, 8, 0, time.UTC)
	exclusions, err := NewExclusions([]string{"excluded"}, nil)
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}

	newNamespaceFixture := func(namespace string) []runtime.Object {
		annotatedSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name:        "checkout-sa",
			Namespace:   namespace,
			Annotations: map[string]string{serviceAccountRoleARNAnnotation: namespace + "-role"},
		}}
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: namespace},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{},
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "checkout-sa"}},
			},
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-pod", Namespace: namespace},
			Spec: corev1.PodSpec{
				ServiceAccountName:           "checkout-sa",
				AutomountServiceAccountToken: boolPtr(false),
				Containers:                   []corev1.Container{{Name: "app"}},
			},
		}
		return []runtime.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
			annotatedSA, deployment, pod,
		}
	}

	objects := append(newNamespaceFixture("excluded"), newNamespaceFixture("kept")...)
	client := fake.NewSimpleClientset(objects...)
	allowServiceAccountList(client, true)

	scanner := &ServiceAccountScanner{now: func() time.Time { return observedAt }}
	result, err := scanner.auditWithEvidence(context.Background(), client, AuditConfig{
		Cluster:    "prod",
		Exclusions: exclusions,
	})
	if err != nil {
		t.Fatalf("auditWithEvidence() error = %v", err)
	}

	// The excluded namespace must contribute zero positive edges.
	for _, edge := range result.ClusterPositiveEdges {
		if edge.Namespace() == "excluded" {
			t.Fatalf("excluded namespace produced a positive edge: %#v", edge)
		}
	}
	// The excluded namespace must have no coverage entry at all.
	for _, coverage := range result.Coverage {
		if coverage.Namespace == "excluded" {
			t.Fatalf("excluded namespace produced a coverage entry: %#v", coverage)
		}
	}

	// Control: the identically shaped "kept" namespace proves the fixture is
	// meaningful — it emits all three edge kinds and exactly one coverage entry.
	keptEdges := 0
	for _, edge := range result.ClusterPositiveEdges {
		if edge.Namespace() == "kept" {
			keptEdges++
		}
	}
	if keptEdges != 3 {
		t.Fatalf("kept namespace edges = %d, want 3 (annotation, workload, pod)", keptEdges)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].Namespace != "kept" ||
		result.Coverage[0].State != NamespaceCoverageComplete {
		t.Fatalf("coverage = %#v, want only kept namespace complete", result.Coverage)
	}
}

// WO-6: Model definitive SSAR permission without weakening production checks.
func allowServiceAccountList(client *fake.Clientset, allowed bool) {
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed},
		}, nil
	})
}
