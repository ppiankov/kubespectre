package k8s

import (
	"context"
	"errors"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// WO-42@v2: shared fixture -- a DaemonSet whose rollout classifies as "running".
func runningDaemonSetStatus() appsv1.DaemonSetStatus {
	return appsv1.DaemonSetStatus{NumberAvailable: 3, NumberUnavailable: 0}
}

// WO-42@v2: image-path matching must normalize docker.io/library/*, scoped
// registries, private re-tags, and digests to the bare repository name, and
// must never match a decoy that merely shares a prefix.
func TestObserveNetworkingComponents_ImageMatching(t *testing.T) {
	cases := []struct {
		name      string
		image     string
		wantMatch bool
		wantHint  string
	}{
		{"docker hub implicit library", "cilium:v1.16.0", true, "cilium"},
		{"docker hub explicit library", "docker.io/library/cilium:v1.16.0", true, "cilium"},
		{"scoped registry", "quay.io/cilium/cilium:v1.16.0", true, "cilium"},
		{"private registry retag", "myregistry.example.com:5000/mirror/cilium:v1.16.0", true, "cilium"},
		{"digest reference", "quay.io/cilium/cilium@sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", true, "cilium"},
		{"calico-node", "docker.io/calico/node:v3.28.0", true, "calico-node"},
		{"aws network policy agent", "602401143452.dkr.ecr.eu-central-1.amazonaws.com/amazon/aws-network-policy-agent:v1.3.1-eksbuild.1", true, "aws-network-policy-agent"},
		{"decoy operator", "quay.io/cilium/cilium-operator:v1.16.0", false, ""},
		{"decoy envoy", "quay.io/cilium/cilium-envoy:v1.16.0", false, ""},
		{"decoy mock", "example.com/cilium-mock:v1.0.0", false, ""},
		{"unrelated image", "nginx:latest", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp, ok := matchNetworkingFingerprint(tc.image)
			if ok != tc.wantMatch {
				t.Fatalf("matchNetworkingFingerprint(%q) matched=%v, want %v", tc.image, ok, tc.wantMatch)
			}
			if ok && fp.hint != tc.wantHint {
				t.Errorf("matchNetworkingFingerprint(%q) hint=%q, want %q", tc.image, fp.hint, tc.wantHint)
			}
		})
	}
}

// WO-42@v2: a cluster with both an AWS-style and a Calico DaemonSet must yield
// TWO independent observations -- neither reduces or masks the other.
func TestObserveNetworkingComponents_MultiCNINoReduction(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: "kube-system"},
			Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "aws-node", Image: "amazon-k8s-cni:v1.21.1", Env: []corev1.EnvVar{{Name: networkPolicyEnforcingModeEnvVar, Value: "standard"}}},
					{Name: "aws-eks-nodeagent", Image: "amazon/aws-network-policy-agent:v1.3.1-eksbuild.1"},
				},
			}}},
			Status: runningDaemonSetStatus(),
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "kube-system"},
			Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "calico-node", Image: "docker.io/calico/node:v3.28.0"}},
			}}},
			Status: runningDaemonSetStatus(),
		},
	)

	obs := ObserveNetworkingComponents(context.Background(), client)
	if len(obs.FingerprintMatches) != 2 {
		t.Fatalf("got %d matches, want 2 (multi-CNI must not reduce to one)", len(obs.FingerprintMatches))
	}
	hints := map[string]bool{}
	for _, m := range obs.FingerprintMatches {
		hints[m.ImplementationHint] = true
	}
	if !hints["aws-network-policy-agent"] || !hints["calico-node"] {
		t.Errorf("hints = %+v, want both aws-network-policy-agent and calico-node present", hints)
	}
}

// WO-42@v2: env resolution must be scanned across every container in the pod
// template (the sibling-container case: AWS carries the mode env var on
// aws-node, not on aws-eks-nodeagent whose image the fingerprint matches).
func TestObserveNetworkingComponents_EnforcingModeLiteral(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "aws-node", Image: "amazon-k8s-cni:v1.21.1", Env: []corev1.EnvVar{{Name: networkPolicyEnforcingModeEnvVar, Value: "standard"}}},
				{Name: "aws-eks-nodeagent", Image: "amazon/aws-network-policy-agent:v1.3.1-eksbuild.1"},
			},
		}}},
		Status: runningDaemonSetStatus(),
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if len(obs.FingerprintMatches) != 1 {
		t.Fatalf("got %d matches, want 1", len(obs.FingerprintMatches))
	}
	if obs.FingerprintMatches[0].EnforcingMode != "mode_literal:standard" {
		t.Errorf("enforcing_mode = %q, want mode_literal:standard", obs.FingerprintMatches[0].EnforcingMode)
	}
}

// WO-42@v2: a literal "none" value must resolve to mode_none, not mode_literal.
func TestObserveNetworkingComponents_EnforcingModeNone(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "aws-node", Image: "amazon-k8s-cni:v1.21.1", Env: []corev1.EnvVar{{Name: networkPolicyEnforcingModeEnvVar, Value: "none"}}},
				{Name: "aws-eks-nodeagent", Image: "amazon/aws-network-policy-agent:v1.3.1-eksbuild.1"},
			},
		}}},
		Status: runningDaemonSetStatus(),
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if obs.FingerprintMatches[0].EnforcingMode != "mode_none" {
		t.Errorf("enforcing_mode = %q, want mode_none", obs.FingerprintMatches[0].EnforcingMode)
	}
}

// WO-42@v2: an env var set via ValueFrom cannot be statically resolved --
// must report mode_via_ref_unresolved, never guess a value.
func TestObserveNetworkingComponents_EnforcingModeViaRefUnresolvedValueFrom(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "aws-node", Image: "amazon-k8s-cni:v1.21.1", Env: []corev1.EnvVar{
					{Name: networkPolicyEnforcingModeEnvVar, ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "mode"}}},
				}},
				{Name: "aws-eks-nodeagent", Image: "amazon/aws-network-policy-agent:v1.3.1-eksbuild.1"},
			},
		}}},
		Status: runningDaemonSetStatus(),
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if obs.FingerprintMatches[0].EnforcingMode != "mode_via_ref_unresolved" {
		t.Errorf("enforcing_mode = %q, want mode_via_ref_unresolved", obs.FingerprintMatches[0].EnforcingMode)
	}
}

// WO-42@v2: the envFrom blind spot -- an EnvFrom source could inject the mode
// env var without any directly-visible Env entry, so its mere presence on
// ANY container must also report unresolved, never absent.
func TestObserveNetworkingComponents_EnforcingModeViaRefUnresolvedEnvFrom(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "aws-node", Image: "amazon-k8s-cni:v1.21.1", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{}}}},
				{Name: "aws-eks-nodeagent", Image: "amazon/aws-network-policy-agent:v1.3.1-eksbuild.1"},
			},
		}}},
		Status: runningDaemonSetStatus(),
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if obs.FingerprintMatches[0].EnforcingMode != "mode_via_ref_unresolved" {
		t.Errorf("enforcing_mode = %q, want mode_via_ref_unresolved", obs.FingerprintMatches[0].EnforcingMode)
	}
}

// WO-42@v2: no env var, no ValueFrom, no EnvFrom anywhere -- must resolve to
// mode_absent, never guessed as active or inactive.
func TestObserveNetworkingComponents_EnforcingModeAbsent(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "aws-node", Image: "amazon-k8s-cni:v1.21.1"},
				{Name: "aws-eks-nodeagent", Image: "amazon/aws-network-policy-agent:v1.3.1-eksbuild.1"},
			},
		}}},
		Status: runningDaemonSetStatus(),
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if obs.FingerprintMatches[0].EnforcingMode != "mode_absent" {
		t.Errorf("enforcing_mode = %q, want mode_absent", obs.FingerprintMatches[0].EnforcingMode)
	}
}

// WO-42@v2: rollout status must classify on NumberAvailable/NumberUnavailable
// only, never NumberReady.
func TestRolloutFromDaemonSetStatus(t *testing.T) {
	cases := []struct {
		name   string
		status appsv1.DaemonSetStatus
		want   NetworkingObservationRollout
	}{
		{"running", appsv1.DaemonSetStatus{NumberAvailable: 3, NumberUnavailable: 0, NumberReady: 0}, NetworkingRolloutRunning},
		{"incomplete", appsv1.DaemonSetStatus{NumberAvailable: 2, NumberUnavailable: 1}, NetworkingRolloutIncomplete},
		{"not running", appsv1.DaemonSetStatus{NumberAvailable: 0, NumberUnavailable: 3}, NetworkingRolloutNotRunning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rolloutFromDaemonSetStatus(tc.status); got != tc.want {
				t.Errorf("rolloutFromDaemonSetStatus(%+v) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

// WO-42@v2: no matching DaemonSets must yield an empty (not nil) list, plus the
// always-present limitations -- never a negative capability conclusion.
func TestObserveNetworkingComponents_EmptyIsNotNegative(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "kube-proxy", Image: "registry.k8s.io/kube-proxy:v1.30.0"}},
		}}},
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if obs.FingerprintMatches == nil {
		t.Error("FingerprintMatches is nil, want an empty non-nil slice")
	}
	if len(obs.FingerprintMatches) != 0 {
		t.Errorf("got %d matches, want 0", len(obs.FingerprintMatches))
	}
	if len(obs.Limitations) == 0 {
		t.Error("Limitations must always be present, even when fingerprint_matches is empty")
	}
	if len(obs.ObservationErrors) != 0 {
		t.Errorf("observation_errors = %v, want none (list succeeded)", obs.ObservationErrors)
	}
}

// WO-42@v2: a failed DaemonSet list must produce an observation error, never a
// false empty that reads identically to "checked, found nothing."
func TestObserveNetworkingComponents_ListFailureIsObservationError(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})

	obs := ObserveNetworkingComponents(context.Background(), client)
	if len(obs.ObservationErrors) == 0 {
		t.Error("ObservationErrors is empty, want the list failure recorded")
	}
	if obs.FingerprintMatches == nil || len(obs.FingerprintMatches) != 0 {
		t.Errorf("FingerprintMatches = %+v, want an empty (non-nil) list even on list failure", obs.FingerprintMatches)
	}
	if len(obs.Limitations) == 0 {
		t.Error("Limitations must still be present on a list failure")
	}
}

// WO-42@v2: STRONG SEPARATION INVARIANT -- networking observations must never
// alter MISSING_NETWORK_POLICY's existence, severity, message, or metadata.
// Cross-product: observations present / absent / errored, each against the
// same policy-less namespace, must all produce a byte-identical finding.
func TestStrongSeparationInvariant_MissingNetworkPolicyUnaffected(t *testing.T) {
	newNamespace := func() *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}
	}

	buildClient := func(withObservations, withListFailure bool) *fake.Clientset {
		objs := []runtime.Object{newNamespace()}
		if withObservations {
			objs = append(objs, &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "kube-system"},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "calico-node", Image: "docker.io/calico/node:v3.28.0"}},
				}}},
				Status: runningDaemonSetStatus(),
			})
		}
		client := fake.NewSimpleClientset(objs...)
		if withListFailure {
			client.PrependReactor("list", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("forbidden")
			})
		}
		return client
	}

	var findings []Finding
	scenarios := []struct {
		name             string
		withObservations bool
		withListFailure  bool
	}{
		{"no daemonsets (empty observations)", false, false},
		{"matching daemonsets (present observations)", true, false},
		{"daemonset list denied (errored observations)", false, true},
	}

	multi := NewMultiAuditor(nil, []Auditor{&NetworkPolicyScanner{}}, 1)
	for _, sc := range scenarios {
		client := buildClient(sc.withObservations, sc.withListFailure)
		multi.client = client
		result, err := multi.AuditAll(context.Background(), AuditConfig{})
		if err != nil {
			t.Fatalf("[%s] AuditAll() error = %v", sc.name, err)
		}
		var mnp *Finding
		for i := range result.Findings {
			if result.Findings[i].ID == FindingMissingNetworkPolicy {
				mnp = &result.Findings[i]
				break
			}
		}
		if mnp == nil {
			t.Fatalf("[%s] no MISSING_NETWORK_POLICY finding produced", sc.name)
		}
		if findings == nil {
			findings = append(findings, *mnp)
			continue
		}
		if !reflect.DeepEqual(findings[0], *mnp) {
			t.Errorf("[%s] MISSING_NETWORK_POLICY finding differs from baseline:\nbaseline=%+v\ngot=%+v", sc.name, findings[0], *mnp)
		}
	}
}
