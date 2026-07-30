package k8s

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
)

// WO-47: NodeScanner audits Node objects for degraded conditions and
// outdated kubelet versions. Kubespectre's whole architecture is a single,
// read-only, Kubernetes-API-only binary -- this scanner reads only
// Node.Status and the API server's own version, never a node's filesystem or
// the kubelet's runtime configuration (anonymous-auth, authorization-mode,
// read-only-port, etc.). A full CIS-Kubernetes-Benchmark-style node audit
// requires node-local access this architecture structurally does not have;
// kube-bench and Kubescape solve that with a privileged pod/host-sensor on
// each node, a different architecture entirely. See
// docs/plans/2026-07-31-wo-node-auditing-design.md.
type NodeScanner struct{}

// WO-47: registers this auditor's identity for MultiAuditor dispatch.
func (s *NodeScanner) Name() string { return "node" }

func (s *NodeScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	// WO-47: preserve the posture-only contract; discard the scanned-object count.
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-47: nodeProblemConditions is a closed, fixed allowlist of the standard
// Kubernetes condition types where status=True means a problem. This must
// stay closed, never a blanket "any non-Ready condition that is True is
// bad" rule: EKS Auto Mode nodes report additional condition types
// (NetworkingReady, KernelReady, StorageReady, ContainerRuntimeReady,
// AcceleratedHardwareReady) where True means healthy -- the OPPOSITE
// polarity. An unrecognized condition type is never inspected for polarity
// at all, confirmed empirically against a real EKS Auto Mode cluster where a
// blanket rule would have produced 4 false positives.
var nodeProblemConditions = map[corev1.NodeConditionType]bool{
	corev1.NodeMemoryPressure:     true,
	corev1.NodeDiskPressure:       true,
	corev1.NodePIDPressure:        true,
	corev1.NodeNetworkUnavailable: true,
}

// WO-47: auditWithCount reports the Nodes examined for degraded conditions
// and kubelet version currency.
func (s *NodeScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list nodes: %w", err)
	}

	// WO-47: a failed server-version lookup must not abort node condition
	// checks -- the two findings are independent, single-object observations.
	serverVersion, versionErr := client.Discovery().ServerVersion()

	scanned := 0
	for _, node := range nodes.Items {
		if cfg.Exclusions.Matches("", node.Labels) {
			continue
		}
		scanned++

		findings = append(findings, checkNodeConditions(node, cfg.Cluster)...)

		if versionErr == nil {
			if f := checkKubeletVersionOutdated(node, serverVersion, cfg.Cluster); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, scanned, nil
}

// WO-47: checkNodeConditions flags a node reporting a closed-allowlist
// problem condition as True, or Ready as False/Unknown. This is a direct,
// positive read of Node.Status.Conditions already returned by the List
// call -- no inference, no cross-source composition.
func checkNodeConditions(node corev1.Node, cluster string) []Finding {
	var findings []Finding
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			if cond.Status != corev1.ConditionTrue {
				findings = append(findings, Finding{
					ID:           FindingNodeConditionDegraded,
					Severity:     SeverityHigh,
					ResourceType: "Node",
					ResourceID:   node.Name,
					Cluster:      cluster,
					Message:      fmt.Sprintf("node %q reports Ready=%s", node.Name, cond.Status),
					Metadata:     map[string]any{"condition_type": string(cond.Type), "condition_status": string(cond.Status)},
				})
			}
			continue
		}
		if !nodeProblemConditions[cond.Type] {
			// WO-47: unrecognized condition type -- never inspected for
			// polarity, never guessed either way.
			continue
		}
		if cond.Status == corev1.ConditionTrue {
			findings = append(findings, Finding{
				ID:           FindingNodeConditionDegraded,
				Severity:     SeverityHigh,
				ResourceType: "Node",
				ResourceID:   node.Name,
				Cluster:      cluster,
				Message:      fmt.Sprintf("node %q reports %s=True", node.Name, cond.Type),
				Metadata:     map[string]any{"condition_type": string(cond.Type), "condition_status": string(cond.Status)},
			})
		}
	}
	return findings
}

// WO-47: kubernetesVersionPattern extracts major/minor/patch from a version
// string such as "v1.35.6-eks-bca9cf6" -- a small, self-contained parser
// rather than a new semver dependency, since Kubernetes/EKS version strings
// follow this fixed vX.Y.Z[-suffix] shape.
var kubernetesVersionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

type parsedKubeVersion struct {
	major, minor, patch int
}

// WO-47: parseKubeVersion returns ok=false for an unparseable string --
// callers must never guess a comparison result for a version they can't parse.
func parseKubeVersion(s string) (parsedKubeVersion, bool) {
	m := kubernetesVersionPattern.FindStringSubmatch(s)
	if m == nil {
		return parsedKubeVersion{}, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	patch, err3 := strconv.Atoi(m[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return parsedKubeVersion{}, false
	}
	return parsedKubeVersion{major: major, minor: minor, patch: patch}, true
}

// WO-47: isOlderThan compares numerically (major, minor, patch) -- never a
// string comparison, which would incorrectly sort v1.35.6 after v1.35.10.
func (v parsedKubeVersion) isOlderThan(other parsedKubeVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

// WO-47: checkKubeletVersionOutdated compares a node's reported kubelet
// version against the API server's version. Informational framing only --
// this does not claim a Kubernetes skew-policy violation (kubelet may be up
// to 3 MINOR versions behind server) unless the minor-version gap actually
// exceeds that; patch-level differences are common during a rolling
// node-group upgrade and are reported as an observation, not an alarm.
func checkKubeletVersionOutdated(node corev1.Node, server *version.Info, cluster string) *Finding {
	kubeletVersion, ok := parseKubeVersion(node.Status.NodeInfo.KubeletVersion)
	if !ok {
		return nil
	}
	serverVersion, ok := parseKubeVersion(server.GitVersion)
	if !ok {
		return nil
	}
	if !kubeletVersion.isOlderThan(serverVersion) {
		return nil
	}

	minorGap := serverVersion.minor - kubeletVersion.minor
	if kubeletVersion.major != serverVersion.major {
		minorGap = -1 // WO-47: a major-version difference is always reported, gap wording aside.
	}
	message := fmt.Sprintf(
		"node %q kubelet %s is older than the API server's %s",
		node.Name, node.Status.NodeInfo.KubeletVersion, server.GitVersion,
	)
	if minorGap > 3 {
		message += fmt.Sprintf(" (%d minor versions behind, exceeding the documented 3-minor-version skew policy)", minorGap)
	}

	return &Finding{
		ID:           FindingNodeKubeletVersionOutdated,
		Severity:     SeverityLow,
		ResourceType: "Node",
		ResourceID:   node.Name,
		Cluster:      cluster,
		Message:      message,
		Metadata: map[string]any{
			"kubelet_version": node.Status.NodeInfo.KubeletVersion,
			"server_version":  server.GitVersion,
		},
	}
}
