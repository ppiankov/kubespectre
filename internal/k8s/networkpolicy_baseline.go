package k8s

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WO-43: checkDefaultDenyBaseline evaluates the FULL UNION of every
// NetworkPolicy in the namespace that selects all pods (an empty
// podSelector), and emits FindingDefaultDenyBaselineNotDetected when the
// namespace does not match a default-deny baseline shape. This is a
// convention lint, not a vulnerability finding: it carries no severity and
// its message never claims the namespace "is insecure" -- a namespace
// secured entirely by narrow per-pod allow-list policies (no {}-selecting
// policy at all) is a valid, intentional architecture that will also not
// match this baseline shape, and the message says so explicitly.
//
// This check is entirely decoupled from CNI capability/enforcement
// observations (WO-42) -- it reasons only about NetworkPolicy object
// content, never about whether anything is actually enforcing it.
func checkDefaultDenyBaseline(namespace string, policies []networkingv1.NetworkPolicy, cluster string) []Finding {
	selectAll := make([]networkingv1.NetworkPolicy, 0, len(policies))
	for _, p := range policies {
		if isEmptyPodSelector(p.Spec.PodSelector) {
			selectAll = append(selectAll, p)
		}
	}

	if !directionMatchesBaseline(selectAll, networkingv1.PolicyTypeIngress) ||
		!directionMatchesBaseline(selectAll, networkingv1.PolicyTypeEgress) {
		return []Finding{{
			ID: FindingDefaultDenyBaselineNotDetected,
			// WO-43: no severity/vulnerability language -- SeverityLow is used
			// only because Finding.Severity has no "informational" tier; this
			// is a convention-lint observation, not a graded vulnerability.
			Severity:     SeverityLow,
			ResourceType: "Namespace",
			ResourceID:   namespace,
			Namespace:    namespace,
			Cluster:      cluster,
			Message:      fmt.Sprintf("namespace %q does not match a default-deny baseline shape (this is a convention check, not a vulnerability finding -- a namespace secured by narrow per-pod allow-list policies will also not match this shape)", namespace),
		}}
	}
	return nil
}

// WO-43: an empty podSelector ({}) selects every pod in the namespace.
func isEmptyPodSelector(selector metav1.LabelSelector) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

// WO-43: directionMatchesBaseline implements the full-union correctness
// requirement: a direction matches the default-deny baseline only if SOME
// {}-selecting policy denies it (PolicyTypes covers the direction and the
// direction's rule list is empty) AND NO {}-selecting policy allows it
// unconditionally (the {{}} override-bug guard) -- an allow-all rule in any
// {}-selecting policy disqualifies the baseline for that direction
// regardless of what any other {}-selecting policy says, because both
// policies apply additively to the same (all-pods) selection.
func directionMatchesBaseline(selectAll []networkingv1.NetworkPolicy, direction networkingv1.PolicyType) bool {
	denied := false
	allowedAll := false
	for _, p := range selectAll {
		types := effectivePolicyTypes(p)
		if !types[direction] {
			continue
		}
		switch direction {
		case networkingv1.PolicyTypeIngress:
			if len(p.Spec.Ingress) == 0 {
				denied = true
			}
			for _, rule := range p.Spec.Ingress {
				if len(rule.Ports) == 0 && len(rule.From) == 0 {
					allowedAll = true
				}
			}
		case networkingv1.PolicyTypeEgress:
			if len(p.Spec.Egress) == 0 {
				denied = true
			}
			for _, rule := range p.Spec.Egress {
				if len(rule.Ports) == 0 && len(rule.To) == 0 {
					allowedAll = true
				}
			}
		}
	}
	return denied && !allowedAll
}

// WO-43: effectivePolicyTypes applies the NetworkPolicy v1 defaulting rule
// when PolicyTypes is omitted: Ingress is always implied; Egress is implied
// only when an Egress section is present (Spec.Egress != nil, regardless of
// its length -- a present-but-empty `egress: []` still counts as a section).
func effectivePolicyTypes(p networkingv1.NetworkPolicy) map[networkingv1.PolicyType]bool {
	if len(p.Spec.PolicyTypes) > 0 {
		types := make(map[networkingv1.PolicyType]bool, len(p.Spec.PolicyTypes))
		for _, t := range p.Spec.PolicyTypes {
			types[t] = true
		}
		return types
	}
	types := map[networkingv1.PolicyType]bool{networkingv1.PolicyTypeIngress: true}
	if p.Spec.Egress != nil {
		types[networkingv1.PolicyTypeEgress] = true
	}
	return types
}
