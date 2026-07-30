package k8s

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// WO-43: opt-in flag must be honored -- disabled by default, no finding fires.
func TestCheckDefaultDenyBaseline_DisabledByDefault(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-app", Namespace: "team-a"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
			},
		},
	)

	findings, err := (&NetworkPolicyScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	for _, f := range findings {
		if f.ID == FindingDefaultDenyBaselineNotDetected {
			t.Errorf("DEFAULT_DENY_BASELINE_NOT_DETECTED fired with the flag disabled, want it never fires by default")
		}
	}
}

// WO-43: a genuine default-deny (both directions, no allow-all, empty
// podSelector) must produce no finding when the flag is enabled.
func TestCheckDefaultDenyBaseline_GenuineDefaultDenyNoFinding(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny-all", Namespace: "team-a"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
				// Ingress/Egress both nil -- deny-all for both directions.
			},
		},
	)

	findings, err := (&NetworkPolicyScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", CheckDefaultDenyBaseline: true})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	for _, f := range findings {
		if f.ID == FindingDefaultDenyBaselineNotDetected {
			t.Errorf("got DEFAULT_DENY_BASELINE_NOT_DETECTED for a genuine default-deny namespace, want none")
		}
	}
}

// WO-43: an explicit per-pod allow-list namespace (no {}-selecting policy at
// all) is a valid architecture that also does not match the baseline shape --
// the finding fires, but it must never claim the namespace is insecure.
func TestCheckDefaultDenyBaseline_PerPodAllowListFiresButNotLabeledInsecure(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-web-from-lb", Namespace: "team-a"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "lb"}}}}},
				},
			},
		},
	)

	findings, err := (&NetworkPolicyScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", CheckDefaultDenyBaseline: true})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	var found *Finding
	for i := range findings {
		if findings[i].ID == FindingDefaultDenyBaselineNotDetected {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no DEFAULT_DENY_BASELINE_NOT_DETECTED finding, want one (no {}-selecting policy exists)")
	}
	if found.Severity != "" && found.Severity != SeverityLow {
		t.Errorf("severity = %q, want low/none -- this is a convention lint, not a graded vulnerability", found.Severity)
	}
	// WO-43: the message may reassure the reader this is NOT a vulnerability
	// finding, but must never assert the namespace itself is insecure or
	// lacks restriction -- check for the claim shape, not the bare word.
	for _, bad := range []string{"is insecure", "not restrictive", "is vulnerable"} {
		if strings.Contains(strings.ToLower(found.Message), bad) {
			t.Errorf("message = %q, must never claim the namespace %q", found.Message, bad)
		}
	}
}

// WO-43: the killgate {{}} override-bug guard -- a real default-deny policy
// PLUS a second {}-selecting policy carrying an allow-all ({{}}) rule for the
// same direction must NOT be detected as a baseline, because both policies
// apply additively to the same (all-pods) selection and the allow-all wins.
func TestCheckDefaultDenyBaseline_AllowAllOverrideGuard(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny-all", Namespace: "team-a"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "sneaky-allow-all-ingress", Namespace: "team-a"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				// {{}} -- one rule with nil From/Ports = allow ALL ingress.
				Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
			},
		},
	)

	findings, err := (&NetworkPolicyScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", CheckDefaultDenyBaseline: true})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.ID == FindingDefaultDenyBaselineNotDetected {
			found = true
		}
	}
	if !found {
		t.Fatal("no DEFAULT_DENY_BASELINE_NOT_DETECTED finding, want one -- the allow-all override must disqualify the baseline")
	}
}

// WO-43: omitted PolicyTypes must be defaulted per the NetworkPolicy v1 spec:
// Ingress always implied; Egress implied only when an Egress section (even an
// empty one) is present.
func TestCheckDefaultDenyBaseline_OmittedPolicyTypesDefaulting(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "implicit-both-directions", Namespace: "team-a"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				// PolicyTypes omitted: Ingress implied (nil Ingress -> deny),
				// Egress implied because Egress section (empty, non-nil) is present.
				Egress: []networkingv1.NetworkPolicyEgressRule{},
			},
		},
	)

	findings, err := (&NetworkPolicyScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test", CheckDefaultDenyBaseline: true})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	for _, f := range findings {
		if f.ID == FindingDefaultDenyBaselineNotDetected {
			t.Errorf("got DEFAULT_DENY_BASELINE_NOT_DETECTED, want none -- omitted PolicyTypes should default to both directions denied here")
		}
	}
}

// WO-43: decoupled from CNI capability -- the check does not read
// EnvironmentObservations at all; confirm it still fires correctly regardless
// of what networking observations are (or are not) present.
func TestCheckDefaultDenyBaseline_DecoupledFromCNICapability(t *testing.T) {
	findings := checkDefaultDenyBaseline("team-a", []networkingv1.NetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-web-from-lb"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		},
	}, "test")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 -- function takes no CNI-capability input at all", len(findings))
	}
}
