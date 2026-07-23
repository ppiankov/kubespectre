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
	// WO-18: Keep the RBAC command on the same audited flag-registration path.
	addAuditFlags(rbacCmd, false)

	rootCmd.AddCommand(rbacCmd)
}

func runRBAC(cmd *cobra.Command, _ []string) error {
	return runAuditWithAuditors(cmd, k8s.RBACOnlyAuditors())
}
