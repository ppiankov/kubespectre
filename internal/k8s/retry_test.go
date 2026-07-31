package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// WO-48: a transient error succeeding within the attempt bound must return
// the eventual successful result, not the error.
func TestRetryTransient_SucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	result, err := retryTransient(context.Background(), func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("stream error when reading response body; INTERNAL_ERROR; received from peer")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %q, want %q", result, "ok")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

// WO-48: a permanent error must never be retried -- fails on the first
// attempt, identical to pre-WO-48 behavior.
func TestRetryTransient_PermanentErrorNeverRetried(t *testing.T) {
	calls := 0
	permanent := k8serrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "x", errors.New("denied"))
	_, err := retryTransient(context.Background(), func() (string, error) {
		calls++
		return "", permanent
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry for a permanent error)", calls)
	}
}

// WO-48: exceeding the attempt bound with only transient errors returns the
// last error, having made exactly retryMaxAttempts calls.
func TestRetryTransient_ExhaustsBoundOnPersistentTransientError(t *testing.T) {
	calls := 0
	_, err := retryTransient(context.Background(), func() (string, error) {
		calls++
		return "", errors.New("unexpected EOF")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != retryMaxAttempts {
		t.Errorf("calls = %d, want %d", calls, retryMaxAttempts)
	}
}

// WO-48: an already-expired context must not be retried -- retrying cannot
// succeed and would only spend an already-exhausted --timeout budget.
func TestRetryTransient_ExpiredContextNeverRetried(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	_, err := retryTransient(ctx, func() (string, error) {
		calls++
		return "", errors.New("stream error; INTERNAL_ERROR")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry once the context is already done)", calls)
	}
}

// WO-48: the total added wait across retries must stay bounded so a retrying
// call can never itself exhaust a healthy cluster's --timeout budget.
func TestRetryTransient_TotalWaitIsBounded(t *testing.T) {
	start := time.Now()
	calls := 0
	_, _ = retryTransient(context.Background(), func() (string, error) {
		calls++
		return "", errors.New("connection reset by peer")
	})
	elapsed := time.Since(start)
	if elapsed > retryMaxTotalWait+time.Second {
		t.Errorf("elapsed = %v, want <= %v (plus scheduling slack)", elapsed, retryMaxTotalWait+time.Second)
	}
}

// WO-48: SecretScanner must recover the full result when the secrets List
// call fails with a transient network error before eventually succeeding --
// not silently drop the auditor's findings for the run as it did pre-WO-48.
func TestSecretScanner_RecoversFromTransientListError(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s1",
				Namespace:         "default",
				CreationTimestamp: metav1.NewTime(time.Now().AddDate(0, 0, -1)),
			},
			Type: corev1.SecretTypeOpaque,
		},
	)
	calls := 0
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls < 2 {
			return true, nil, errors.New("stream error when reading response body; INTERNAL_ERROR; received from peer")
		}
		return false, nil, nil
	})

	scanner := &SecretScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error after transient recovery: %v", err)
	}
	// s1 is recent and unmounted -> exactly one UNUSED_SECRET_MOUNT finding.
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (auditor should have recovered, not returned zero findings)", len(findings))
	}
}

// WO-48: ProveNamespaceCoverage must never retry a permanent SSAR denial --
// exactly one Create call, coverage reported unknown, identical to pre-WO-48.
func TestProveNamespaceCoverage_PermanentDenialNeverRetried(t *testing.T) {
	client := fake.NewSimpleClientset()
	calls := 0
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, nil, k8serrors.NewForbidden(schema.GroupResource{Resource: "selfsubjectaccessreviews"}, "x", errors.New("denied"))
	})

	coverage, err := ProveNamespaceCoverage(context.Background(), client, "payments")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry for a permanent denial)", calls)
	}
	if coverage.State != NamespaceCoverageUnknown {
		t.Errorf("state = %q, want unknown", coverage.State)
	}
}

// WO-48: ProveNamespaceCoverage must recover from a transient SSAR failure
// instead of reporting the namespace's coverage as unproven for the run.
func TestProveNamespaceCoverage_RecoversFromTransientError(t *testing.T) {
	client := fake.NewSimpleClientset()
	calls := 0
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls < 2 {
			return true, nil, errors.New("unexpected EOF")
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
		t.Errorf("state = %q, want complete (should have recovered from the transient error)", coverage.State)
	}
}
