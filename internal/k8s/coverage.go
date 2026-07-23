package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var errCoverageClientUnavailable = errors.New("kubernetes client is unavailable")

// WO-6: NamespaceCoverageState is boolean-backed so only unknown and complete are representable.
type NamespaceCoverageState bool

// WO-6: Keep the coverage vocabulary structurally limited to unknown and complete.
const (
	NamespaceCoverageUnknown  NamespaceCoverageState = false // WO-6: proof is absent or incomplete.
	NamespaceCoverageComplete NamespaceCoverageState = true  // WO-6: SSAR and enumeration both succeeded.
)

// String returns the WO-6 artifact vocabulary for a coverage state.
// WO-6: Keep artifact rendering deterministic for the sealed coverage states.
func (s NamespaceCoverageState) String() string {
	if s == NamespaceCoverageComplete {
		return "complete"
	}
	return "unknown"
}

// MarshalJSON emits the WO-6 state as its declared artifact string.
// WO-6: Serialize coverage with the ratified string vocabulary.
func (s NamespaceCoverageState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// WO-11: UnmarshalJSON keeps artifact input sealed to the two declared coverage states.
func (s *NamespaceCoverageState) UnmarshalJSON(data []byte) error {
	*s = NamespaceCoverageUnknown
	var state string
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode namespace coverage state: %w", err)
	}

	switch state {
	case NamespaceCoverageUnknown.String():
		*s = NamespaceCoverageUnknown
	case NamespaceCoverageComplete.String():
		*s = NamespaceCoverageComplete
	default:
		return fmt.Errorf("invalid namespace coverage state %q", state)
	}
	return nil
}

// WO-6: NamespaceCoverage exposes artifact-level scope without making an absence claim.
type NamespaceCoverage struct {
	Namespace  string                 `json:"namespace"`   // WO-6: the exact namespace whose scope was probed.
	State      NamespaceCoverageState `json:"state"`       // WO-6: complete only after proof and enumeration.
	ObservedAt time.Time              `json:"observed_at"` // WO-6: source-collection time for the proof.
}

// WO-6: ProveNamespaceCoverage fails closed unless SSAR definitively allows SA enumeration.
func ProveNamespaceCoverage(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
) (NamespaceCoverage, error) {
	coverage := NamespaceCoverage{
		Namespace:  namespace,
		State:      NamespaceCoverageUnknown,
		ObservedAt: time.Now().UTC(),
	}
	if client == nil {
		return coverage, errCoverageClientUnavailable
	}
	if namespace == "" {
		return coverage, errors.New("namespace is required")
	}

	review, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(
		ctx,
		&authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Verb:      "list",
					Resource:  "serviceaccounts",
				},
			},
		},
		metav1.CreateOptions{},
	)
	coverage.ObservedAt = time.Now().UTC()
	if err != nil {
		return coverage, fmt.Errorf("create serviceaccount SSAR for namespace %q: %w", namespace, err)
	}
	// WO-6: denial or an absent evaluation leaves the default unknown state intact.
	if review == nil {
		return coverage, errors.New("serviceaccount SSAR returned no evaluation")
	}
	if review.Status.Allowed {
		coverage.State = NamespaceCoverageComplete
	}
	return coverage, nil
}
