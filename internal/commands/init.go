package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initFlags struct {
	force bool
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate sample config and RBAC policy",
	Long:  `Creates a sample .kubespectre.yaml and kubespectre-rbac.yaml with default settings.`,
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initFlags.force, "force", false, "Overwrite existing files")
	rootCmd.AddCommand(initCmd)
}

func runInit(_ *cobra.Command, _ []string) error {
	configPath := ".kubespectre.yaml"
	rbacPath := "kubespectre-rbac.yaml"

	if err := writeIfNotExists(configPath, sampleConfig, initFlags.force); err != nil {
		return err
	}
	if err := writeIfNotExists(rbacPath, sampleRBAC, initFlags.force); err != nil {
		return err
	}

	fmt.Printf("Created %s and %s\n", configPath, rbacPath)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Edit .kubespectre.yaml to configure trusted registries")
	fmt.Println("  2. Apply RBAC policy: kubectl apply -f kubespectre-rbac.yaml")
	fmt.Println("  3. Run: kubespectre audit")
	return nil
}

func writeIfNotExists(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(path, []byte(content), 0o644)
}

const sampleConfig = `# kubespectre configuration
# See: https://github.com/ppiankov/kubespectre

# Namespace to audit (omit to scan all namespaces)
# namespace: default

# Stale secret threshold (days)
stale_days: 90

# Minimum severity to report: critical, high, medium, low
severity_min: low

# Output format: text, json, sarif, spectrehub
format: text

# Audit timeout
timeout: 5m

# Trusted container registries (images from other registries get flagged)
trusted_registries:
  # - gcr.io/my-project
  # - us-docker.pkg.dev/my-project
  # - 123456789.dkr.ecr.us-east-1.amazonaws.com

# Namespaces to exclude from auditing
# exclude:
#   namespaces:
#     - kube-system
#     - kube-public
`

const sampleRBAC = `# kubespectre ClusterRole and ClusterRoleBinding
# Apply: kubectl apply -f kubespectre-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubespectre
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubespectre
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets", "serviceaccounts", "namespaces"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["persistentvolumeclaims"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubespectre
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubespectre
subjects:
- kind: ServiceAccount
  name: kubespectre
  namespace: kube-system
`
