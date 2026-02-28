package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeOpts holds optional overrides for building Kubernetes clients.
type KubeOpts struct {
	Kubeconfig string
	Context    string
}

// expandTilde replaces a leading ~ with the user's home directory.
func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// buildConfigFromOpts builds a rest.Config using clientcmd loading rules.
func buildConfigFromOpts(kubeconfigPath, contextOverride string) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = expandTilde(kubeconfigPath)
	}

	overrides := &clientcmd.ConfigOverrides{}
	if contextOverride != "" {
		overrides.CurrentContext = contextOverride
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
}

// BuildClient builds a Kubernetes clientset.
//
// Priority:
//  1. explicit kubeconfig path + context override
//  2. $KUBECONFIG + context override
//  3. default ~/.kube/config + context override
//  4. in-cluster config (context override ignored)
func BuildClient(opts KubeOpts) (*kubernetes.Clientset, error) {
	cfg, err := buildRestConfig(opts)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("new clientset: %w", err)
	}
	return clientset, nil
}

func buildRestConfig(opts KubeOpts) (*rest.Config, error) {
	if opts.Context != "" {
		return buildConfigFromOpts(opts.Kubeconfig, opts.Context)
	}

	if opts.Kubeconfig != "" {
		return buildConfigFromOpts(opts.Kubeconfig, "")
	}

	if env := os.Getenv("KUBECONFIG"); env != "" {
		return buildConfigFromOpts(env, "")
	}

	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}

	return buildConfigFromOpts("", "")
}
