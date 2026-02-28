package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PodSecurityScanner audits pods for privileged containers,
// hostNetwork, and hostPID violations.
type PodSecurityScanner struct{}

func (s *PodSecurityScanner) Name() string { return "pod-security" }

func (s *PodSecurityScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	var findings []Finding

	listOpts := metav1.ListOptions{}
	var pods *corev1.PodList
	var err error

	if cfg.Namespace != "" {
		pods, err = client.CoreV1().Pods(cfg.Namespace).List(ctx, listOpts)
	} else {
		pods, err = client.CoreV1().Pods("").List(ctx, listOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	for _, pod := range pods.Items {
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

		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
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
		}
	}

	return findings, nil
}
