package commands

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/ppiankov/kubespectre/internal/report"
)

// enhanceError wraps an error with context and suggestions for common K8s issues.
func enhanceError(action string, err error) error {
	msg := err.Error()

	var hint string
	switch {
	case strings.Contains(msg, "no configuration has been provided"):
		hint = "No kubeconfig found. Set KUBECONFIG or use --kubeconfig flag"
	case strings.Contains(msg, "Unauthorized") || strings.Contains(msg, "401"):
		hint = "Authentication failed. Check your kubeconfig credentials or context"
	case strings.Contains(msg, "Forbidden") || strings.Contains(msg, "403"):
		hint = "Insufficient permissions. kubespectre needs ClusterRole with get/list on target resources"
	case strings.Contains(msg, "connection refused"):
		hint = "Cannot reach the Kubernetes API server. Verify the cluster is running and accessible"
	case strings.Contains(msg, "context deadline exceeded"):
		hint = "Operation timed out. Try increasing --timeout or narrowing --namespace scope"
	}

	if hint != "" {
		return fmt.Errorf("%s: %w\n  hint: %s", action, err, hint)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// computeTargetHash generates a SHA256 hash for the target URI.
func computeTargetHash(cluster, ns string) string {
	input := fmt.Sprintf("cluster:%s,namespace:%s", cluster, ns)
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", h)
}

// selectReporter creates the appropriate reporter for the given format.
func selectReporter(format, outputFile string) (report.Reporter, error) {
	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	switch format {
	case "json":
		return &report.JSONReporter{Writer: w}, nil
	case "text":
		return &report.TextReporter{Writer: w}, nil
	case "sarif":
		return &report.SARIFReporter{Writer: w}, nil
	case "spectrehub":
		return &report.SpectreHubReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, or spectrehub)", format)
	}
}
