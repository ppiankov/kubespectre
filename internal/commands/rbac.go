package commands

import (
	"github.com/ppiankov/kubespectre/internal/k8s"
	"github.com/spf13/cobra"
)

var rbacCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Audit RBAC permissions only",
	Long: `Run RBAC-only security audit: check ClusterRoleBindings for wildcard
permissions and cluster-admin bindings to non-system service accounts.`,
	RunE: runRBAC,
}

func init() {
	rbacCmd.Flags().StringVar(&auditFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	rbacCmd.Flags().StringVarP(&auditFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	rbacCmd.Flags().StringVar(&auditFlags.severityMin, "severity-min", "low", "Minimum severity: critical, high, medium, low")
	rbacCmd.Flags().DurationVar(&auditFlags.timeout, "timeout", auditFlags.timeout, "Audit timeout")

	rootCmd.AddCommand(rbacCmd)
}

func runRBAC(cmd *cobra.Command, _ []string) error {
	return runAuditWithAuditors(cmd, k8s.RBACOnlyAuditors())
}
