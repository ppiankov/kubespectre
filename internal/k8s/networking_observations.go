package k8s

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WO-42@v2: NetworkingObservationRollout is the DaemonSet-local readiness state
// for a matched networking-component object. This is object-local rollout
// status, never a cluster-wide enforcement verdict.
type NetworkingObservationRollout string

// WO-42@v2: closed four-state rollout vocabulary; never gate on NumberReady alone.
const (
	NetworkingRolloutRunning          NetworkingObservationRollout = "running"
	NetworkingRolloutIncomplete       NetworkingObservationRollout = "rollout_incomplete"
	NetworkingRolloutNotRunning       NetworkingObservationRollout = "not_running"
	NetworkingRolloutReadinessUnknown NetworkingObservationRollout = "readiness_unknown"
)

// WO-42@v2: NetworkingObservedResource identifies the exact object a fingerprint
// match came from, so the observation carries resource provenance rather than
// an anonymous claim.
type NetworkingObservedResource struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// WO-42@v2: NetworkingFingerprintMatch is ONE per-object observation. It is
// deliberately NOT a cluster capability verdict -- a cluster may have zero,
// one, or many matches, and none of them mask or supersede another (v3
// deleted the v2 cluster-scoped capability enum for exactly this reason: a
// single reduced state hides multi-CNI coexistence).
type NetworkingFingerprintMatch struct {
	ImplementationHint string                       `json:"implementation_hint"`
	Resource           NetworkingObservedResource   `json:"resource"`
	MatchedSignals     []string                     `json:"matched_signals"`
	Rollout            NetworkingObservationRollout `json:"rollout"`
	// EnforcingMode is AWS-only: resolved from the aws-node DaemonSet's
	// NETWORK_POLICY_ENFORCING_MODE environment configuration. Empty for
	// non-AWS fingerprints.
	EnforcingMode string `json:"enforcing_mode,omitempty"`
}

// WO-42@v2: NetworkingObservations is the per-object inventory plane. It is
// intentionally separate from posture Findings (see the STRONG SEPARATION
// INVARIANT test in networking_observations_test.go) -- this plane makes no
// enforcement, capability, or restrictiveness claim of any kind.
type NetworkingObservations struct {
	FingerprintMatches []NetworkingFingerprintMatch `json:"fingerprint_matches"`
	ObservationErrors  []string                     `json:"observation_errors,omitempty"`
	Limitations        []string                     `json:"limitations"`
}

// WO-42@v2: EnvironmentObservations is the top-level wrapper for this
// non-posture observation surface, kept structurally apart from
// ScanResult.Findings so a future observation category cannot accidentally
// be read as a security finding.
type EnvironmentObservations struct {
	Networking NetworkingObservations `json:"networking"`
}

// WO-42@v2: limitations are always present, regardless of what was or wasn't
// found -- an empty fingerprint_matches list must never be read as a clean
// negative claim without these caveats attached.
var networkingObservationLimitations = []string{
	"presence of a recognized networking-component image does not establish that it is currently enforcing NetworkPolicy on every node",
	"this observation does not test runtime enforcement behavior and is not a substitute for verifying enforcement directly",
	"an empty fingerprint_matches list does not mean no network-policy enforcer is present -- it may use an unrecognized image or naming convention",
}

type networkingComponentFingerprint struct {
	hint          string
	imagePathBase string
	isAWS         bool
}

// WO-42@v2: fingerprints match on path.Base(ref.Context().RepositoryStr()) --
// the last path segment of the image repository, after registry/namespace
// stripping. Exact equality only (never strings.Contains, never full-ref
// comparison) so "cilium-operator"/"cilium-envoy"/"*-mock" decoys do not
// match "cilium".
var networkingComponentFingerprints = []networkingComponentFingerprint{
	{hint: "aws-network-policy-agent", imagePathBase: "aws-network-policy-agent", isAWS: true},
	// WO-42@v2: the upstream Calico node image repository is "calico/node" (e.g.
	// docker.io/calico/node, quay.io/calico/node), so path.Base(RepositoryStr())
	// yields "node", not "calico-node" -- the DaemonSet/container conventionally
	// named "calico-node" is a different string from its image's basename.
	// implementation_hint keeps the human-readable "calico-node" label; the
	// match target below is the real image basename.
	{hint: "calico-node", imagePathBase: "node"},
	{hint: "cilium", imagePathBase: "cilium"},
}

// WO-42@v2: the AWS VPC CNI env var that configures native NetworkPolicy
// enforcement; historically named ENABLE_NETWORK_POLICY, renamed by AWS.
const networkPolicyEnforcingModeEnvVar = "NETWORK_POLICY_ENFORCING_MODE"

// WO-42@v2: ObserveNetworkingComponents lists every DaemonSet cluster-wide once
// and matches container images against a fixed set of known NetworkPolicy-
// capable CNI component fingerprints. This function produces ONLY per-object
// observations -- it must never be composed into a single cluster-level
// capability/enforcement conclusion by any caller (v1 "enforcement active"
// and v2 "cluster capability enum" framings were both rejected by the WO-36
// killgate for exactly this reason).
func ObserveNetworkingComponents(ctx context.Context, client kubernetes.Interface) NetworkingObservations {
	obs := NetworkingObservations{
		FingerprintMatches: []NetworkingFingerprintMatch{},
		Limitations:        append([]string{}, networkingObservationLimitations...),
	}

	// WO-42@v2: a nil client is a test double for isolated auditor-loop testing
	// (see scanner_test.go's NewMultiAuditor(nil, ...) cases) -- treat it the
	// same as "not run," never a false empty, since there was no cluster to check.
	if client == nil {
		obs.ObservationErrors = append(obs.ObservationErrors, "no cluster client available")
		return obs
	}

	daemonsets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// WO-42@v2: a failed list is recorded as an observation error, never a
		// false empty -- an RBAC denial must not read the same as "checked,
		// nothing found."
		obs.ObservationErrors = append(obs.ObservationErrors, fmt.Sprintf("list daemonsets: %v", err))
		return obs
	}

	for _, ds := range daemonsets.Items {
		allContainers := make([]corev1.Container, 0, len(ds.Spec.Template.Spec.Containers)+len(ds.Spec.Template.Spec.InitContainers))
		allContainers = append(allContainers, ds.Spec.Template.Spec.Containers...)
		allContainers = append(allContainers, ds.Spec.Template.Spec.InitContainers...)

		for _, c := range allContainers {
			fp, ok := matchNetworkingFingerprint(c.Image)
			if !ok {
				continue
			}
			match := NetworkingFingerprintMatch{
				ImplementationHint: fp.hint,
				Resource: NetworkingObservedResource{
					Kind:      "DaemonSet",
					Namespace: ds.Namespace,
					Name:      ds.Name,
				},
				MatchedSignals: []string{"container_image=" + c.Image},
				Rollout:        rolloutFromDaemonSetStatus(ds.Status),
			}
			if fp.isAWS {
				match.EnforcingMode = resolveEnforcingMode(allContainers)
			}
			obs.FingerprintMatches = append(obs.FingerprintMatches, match)
		}
	}

	return obs
}

// WO-42@v2: matchNetworkingFingerprint parses the image reference with
// go-containerregistry and compares path.Base(RepositoryStr()) against the
// fixed fingerprint table -- this correctly normalizes docker.io/library/*,
// bare refs, digests, and private-registry re-tags to their bare repository
// name, and rejects an unparseable image rather than guessing.
func matchNetworkingFingerprint(image string) (networkingComponentFingerprint, bool) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return networkingComponentFingerprint{}, false
	}
	base := path.Base(ref.Context().RepositoryStr())
	for _, fp := range networkingComponentFingerprints {
		if base == fp.imagePathBase {
			return fp, true
		}
	}
	return networkingComponentFingerprint{}, false
}

// WO-42@v2: rolloutFromDaemonSetStatus classifies object-local readiness.
// Deliberately never gates on NumberReady alone (per acceptance criteria) --
// only NumberAvailable/NumberUnavailable, which reflect the minReadySeconds-
// aware availability the DaemonSet controller itself uses.
func rolloutFromDaemonSetStatus(status appsv1.DaemonSetStatus) NetworkingObservationRollout {
	switch {
	case status.NumberAvailable > 0 && status.NumberUnavailable == 0:
		return NetworkingRolloutRunning
	case status.NumberAvailable > 0 && status.NumberUnavailable > 0:
		return NetworkingRolloutIncomplete
	case status.NumberAvailable == 0:
		return NetworkingRolloutNotRunning
	default:
		return NetworkingRolloutReadinessUnknown
	}
}

// WO-42@v2: resolveEnforcingMode scans every container in the DaemonSet's pod
// template (not just the matched fingerprint container) for
// NETWORK_POLICY_ENFORCING_MODE, since AWS VPC CNI carries this setting on
// the sibling "aws-node" container, not the aws-eks-nodeagent container the
// image fingerprint matches on. A literal value takes precedence; an
// unresolved reference (ValueFrom, or ANY container-wide EnvFrom -- the
// envFrom blind spot, since it could inject this key without a visible Env
// entry) is reported honestly rather than guessed.
func resolveEnforcingMode(containers []corev1.Container) string {
	sawUnresolvedRef := false
	for _, c := range containers {
		for _, e := range c.Env {
			if e.Name != networkPolicyEnforcingModeEnvVar {
				continue
			}
			if e.ValueFrom != nil {
				sawUnresolvedRef = true
				continue
			}
			if e.Value == "" || strings.EqualFold(e.Value, "none") {
				return "mode_none"
			}
			return "mode_literal:" + e.Value
		}
		if len(c.EnvFrom) > 0 {
			sawUnresolvedRef = true
		}
	}
	if sawUnresolvedRef {
		return "mode_via_ref_unresolved"
	}
	return "mode_absent"
}
