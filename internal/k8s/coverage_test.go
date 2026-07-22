package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// WO-6: Prove definitive SSAR permission yields complete namespace coverage.
func TestProveNamespaceCoverageAllowed(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		review := create.GetObject().(*authorizationv1.SelfSubjectAccessReview)
		attributes := review.Spec.ResourceAttributes
		if attributes == nil || attributes.Verb != "list" || attributes.Resource != "serviceaccounts" || attributes.Namespace != "payments" {
			t.Fatalf("unexpected SSAR attributes: %#v", attributes)
		}
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})

	coverage, err := ProveNamespaceCoverage(context.Background(), client, "payments")
	if err != nil {
		t.Fatalf("prove coverage: %v", err)
	}
	if coverage.State != NamespaceCoverageComplete {
		t.Errorf("state = %q, want complete", coverage.State)
	}
	if coverage.ObservedAt.IsZero() {
		t.Error("observed_at is zero")
	}
}

// WO-6: Prove SSAR denial leaves namespace coverage unknown.
func TestProveNamespaceCoverageDenied(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: false},
		}, nil
	})

	coverage, err := ProveNamespaceCoverage(context.Background(), client, "payments")
	if err != nil {
		t.Fatalf("prove coverage: %v", err)
	}
	if coverage.State != NamespaceCoverageUnknown {
		t.Errorf("state = %q, want unknown", coverage.State)
	}
}

// WO-6: Prove SSAR errors fail closed without completeness claims.
func TestProveNamespaceCoverageErrorFailsClosed(t *testing.T) {
	client := fake.NewSimpleClientset()
	wantErr := errors.New("authorization unavailable")
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})

	coverage, err := ProveNamespaceCoverage(context.Background(), client, "payments")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if coverage.State != NamespaceCoverageUnknown {
		t.Errorf("state = %q, want unknown", coverage.State)
	}
}

// WO-6: Prove a missing client cannot create completeness.
func TestProveNamespaceCoverageAbsentFailsClosed(t *testing.T) {
	coverage, err := ProveNamespaceCoverage(context.Background(), nil, "payments")
	if err == nil {
		t.Fatal("expected unavailable-client error")
	}
	if coverage.State != NamespaceCoverageUnknown {
		t.Errorf("state = %q, want unknown", coverage.State)
	}
}

// WO-6: Prove a missing SSAR evaluation cannot create completeness.
func TestProveNamespaceCoverageMissingEvaluationFailsClosed(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, (*authorizationv1.SelfSubjectAccessReview)(nil), nil
	})

	coverage, err := ProveNamespaceCoverage(context.Background(), client, "payments")
	if err == nil {
		t.Fatal("expected missing-evaluation error")
	}
	if coverage.State != NamespaceCoverageUnknown {
		t.Errorf("state = %q, want unknown", coverage.State)
	}
}

// WO-6: Prove namespace discovery alone cannot establish enumeration coverage.
func TestNamespaceListDoesNotProveCoverage(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "payments"},
	})
	if _, err := client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{}); err != nil {
		t.Fatalf("list namespaces: %v", err)
	}

	coverage, err := ProveNamespaceCoverage(context.Background(), client, "payments")
	if err != nil {
		t.Fatalf("prove coverage: %v", err)
	}
	if coverage.State != NamespaceCoverageUnknown {
		t.Errorf("state = %q after namespace list, want unknown", coverage.State)
	}
}

// WO-6: Lock coverage serialization to complete and unknown.
func TestNamespaceCoverageSerializationHasOnlyCompleteOrUnknown(t *testing.T) {
	for _, state := range []NamespaceCoverageState{NamespaceCoverageUnknown, NamespaceCoverageComplete} {
		coverage := NamespaceCoverage{Namespace: "payments", State: state}
		encoded, err := json.Marshal(coverage)
		if err != nil {
			t.Fatalf("marshal %q coverage: %v", state, err)
		}
		var got NamespaceCoverage
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal coverage: %v", err)
		}
		if got.State != state {
			t.Errorf("round-tripped state = %q, want %q", got.State, state)
		}
	}
}

// WO-11: Keep invalid artifact input fail-closed when values are reused.
func TestNamespaceCoverageRejectsInvalidState(t *testing.T) {
	for _, input := range []string{
		`{"namespace":"payments","state":"partial"}`,
		`{"namespace":"payments","state":{}}`,
	} {
		coverage := NamespaceCoverage{State: NamespaceCoverageComplete}
		if err := json.Unmarshal([]byte(input), &coverage); err == nil {
			t.Errorf("json.Unmarshal(%s) error = nil, want invalid coverage state error", input)
		}
		if coverage.State != NamespaceCoverageUnknown {
			t.Errorf("state = %q after invalid input %s, want unknown", coverage.State, input)
		}
	}
}
