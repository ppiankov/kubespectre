package k8s

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WO-35: defaultDangerousCapabilities is used when AuditConfig.DangerousCapabilities is empty.
var defaultDangerousCapabilities = []string{"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "NET_RAW"}

// PodSecurityScanner audits pods for privileged containers, hostNetwork,
// hostPID, hostPath volumes, dangerous added capabilities, and
// allowPrivilegeEscalation.
type PodSecurityScanner struct{}

func (s *PodSecurityScanner) Name() string { return "pod-security" }

func (s *PodSecurityScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	// WO-25: preserve the posture-only contract; discard the scanned-object count.
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-25: auditWithCount reports the pods examined for pod-security posture.
func (s *PodSecurityScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding

	listOpts := metav1.ListOptions{}
	var pods *corev1.PodList
	var err error

	// WO-48: retry a transient network blip before giving up this auditor's
	// entire finding set for the run.
	if cfg.Namespace != "" {
		pods, err = retryTransient(ctx, func() (*corev1.PodList, error) {
			return client.CoreV1().Pods(cfg.Namespace).List(ctx, listOpts)
		})
	} else {
		pods, err = retryTransient(ctx, func() (*corev1.PodList, error) {
			return client.CoreV1().Pods("").List(ctx, listOpts)
		})
	}
	if err != nil {
		return nil, 0, fmt.Errorf("list pods: %w", err)
	}

	dangerousCaps := cfg.DangerousCapabilities
	if len(dangerousCaps) == 0 {
		dangerousCaps = defaultDangerousCapabilities
	}

	scanned := 0 // WO-33: count only pods that survive exclusion filtering.
	for _, pod := range pods.Items {
		// WO-21: Enforce the operator boundary before producing pod findings.
		if cfg.Exclusions.Matches(pod.Namespace, pod.Labels) {
			continue
		}
		scanned++
		if pod.Spec.HostNetwork {
			findings = append(findings, Finding{
				ID:           FindingHostNetwork,
				Severity:     SeverityCritical,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "pod uses host network",
			})
		}

		if pod.Spec.HostPID {
			findings = append(findings, Finding{
				ID:           FindingHostPID,
				Severity:     SeverityCritical,
				ResourceType: "Pod",
				ResourceID:   pod.Name,
				Namespace:    pod.Namespace,
				Cluster:      cfg.Cluster,
				Message:      "pod uses host PID namespace",
			})
		}

		// WO-35: a hostPath volume lets a container read/write the node filesystem,
		// a common container-escape vector independent of privileged mode.
		for _, v := range pod.Spec.Volumes {
			if v.HostPath != nil {
				findings = append(findings, Finding{
					ID:           FindingHostPathVolume,
					Severity:     SeverityHigh,
					ResourceType: "Pod",
					ResourceID:   pod.Name,
					Namespace:    pod.Namespace,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("volume %q mounts host path %q", v.Name, v.HostPath.Path),
					Metadata:     map[string]any{"volume": v.Name, "path": v.HostPath.Path},
				})
			}
		}

		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			privileged := c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
			if privileged {
				findings = append(findings, Finding{
					ID:           FindingPrivilegedContainer,
					Severity:     SeverityCritical,
					ResourceType: "Pod",
					ResourceID:   pod.Name,
					Namespace:    pod.Namespace,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("container %q runs in privileged mode", c.Name),
				})
			}

			if added := dangerousCapabilitiesAdded(c, dangerousCaps); len(added) > 0 {
				findings = append(findings, Finding{
					ID:           FindingDangerousCapability,
					Severity:     SeverityHigh,
					ResourceType: "Pod",
					ResourceID:   pod.Name,
					Namespace:    pod.Namespace,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("container %q adds capabilities %v", c.Name, added),
					Metadata:     map[string]any{"container": c.Name, "capabilities": added},
				})
			}

			// WO-35: privileged already implies escalation is possible; do not
			// double-flag the same container for both.
			if !privileged && allowsPrivilegeEscalation(c) {
				findings = append(findings, Finding{
					ID:           FindingPrivilegeEscalation,
					Severity:     SeverityMedium,
					ResourceType: "Pod",
					ResourceID:   pod.Name,
					Namespace:    pod.Namespace,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("container %q does not set allowPrivilegeEscalation to false", c.Name),
				})
			}
		}
	}

	// WO-33: report only pods actually examined (post-exclusion), not every pod listed.
	return findings, scanned, nil
}

// WO-35: dangerousCapabilitiesAdded returns which configured dangerous capabilities
// a container's securityContext adds, preserving the configured list's order.
func dangerousCapabilitiesAdded(c corev1.Container, dangerous []string) []string {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return nil
	}
	added := make(map[string]bool, len(c.SecurityContext.Capabilities.Add))
	for _, cap := range c.SecurityContext.Capabilities.Add {
		added[strings.ToUpper(string(cap))] = true
	}
	var matched []string
	for _, d := range dangerous {
		if added[strings.ToUpper(d)] {
			matched = append(matched, d)
		}
	}
	return matched
}

// WO-35: allowsPrivilegeEscalation reports whether a container permits privilege
// escalation. The Kubernetes default is true when unset.
func allowsPrivilegeEscalation(c corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil {
		return true
	}
	return *c.SecurityContext.AllowPrivilegeEscalation
}
