package k8s

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ImageScanner audits container images for missing digest pinning
// and untrusted registries.
type ImageScanner struct{}

func (s *ImageScanner) Name() string { return "image" }

func (s *ImageScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	var findings []Finding

	ns := cfg.Namespace

	pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	seen := make(map[string]bool)

	for _, pod := range pods.Items {
		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			image := c.Image

			// Deduplicate per pod+image to avoid noise
			key := pod.Namespace + "/" + pod.Name + "/" + image
			if seen[key] {
				continue
			}
			seen[key] = true

			if !hasDigest(image) {
				findings = append(findings, Finding{
					ID:           FindingNoImageDigest,
					Severity:     SeverityMedium,
					ResourceType: "Pod",
					ResourceID:   pod.Name,
					Namespace:    pod.Namespace,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("container %q image %q has no digest pin", c.Name, image),
					Metadata:     map[string]any{"image": image, "container": c.Name},
				})
			}

			if len(cfg.TrustedRegistries) > 0 && !isTrustedRegistry(image, cfg.TrustedRegistries) {
				findings = append(findings, Finding{
					ID:           FindingUntrustedRegistry,
					Severity:     SeverityMedium,
					ResourceType: "Pod",
					ResourceID:   pod.Name,
					Namespace:    pod.Namespace,
					Cluster:      cfg.Cluster,
					Message:      fmt.Sprintf("container %q image %q from untrusted registry", c.Name, image),
					Metadata:     map[string]any{"image": image, "container": c.Name},
				})
			}
		}
	}

	return findings, nil
}

// hasDigest returns true if the image reference contains a digest (@sha256:...).
func hasDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}

// isTrustedRegistry returns true if the image is from one of the trusted registries.
func isTrustedRegistry(image string, trusted []string) bool {
	for _, registry := range trusted {
		if strings.HasPrefix(image, registry+"/") || strings.HasPrefix(image, registry+":") || image == registry {
			return true
		}
	}
	// Images without a slash are from Docker Hub (library/)
	// Check if any trusted registry matches docker.io
	if !strings.Contains(image, "/") || isDockerHubShorthand(image) {
		for _, registry := range trusted {
			if registry == "docker.io" || registry == "index.docker.io" {
				return true
			}
		}
	}
	return false
}

func isDockerHubShorthand(image string) bool {
	// Single-segment names like "nginx" or "nginx:latest" are Docker Hub
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		return true
	}
	// Two-segment without dots in first part: "library/nginx" → Docker Hub
	return !strings.Contains(parts[0], ".")
}
