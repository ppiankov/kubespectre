package commands

import (
	"log/slog"

	"github.com/ppiankov/kubespectre/internal/config"
	"github.com/ppiankov/kubespectre/internal/logging"
	"github.com/spf13/cobra"
)

var (
	verbose    bool
	kubeconfig string
	context_   string
	namespace  string
	version    string
	commit     string
	date       string
	cfg        config.Config
)

var rootCmd = &cobra.Command{
	Use:   "kubespectre",
	Short: "kubespectre — Kubernetes security posture auditor",
	Long: `kubespectre audits Kubernetes cluster security posture: RBAC permissions,
pod security standards, network policies, secrets lifecycle, service accounts,
image provenance, and audit logging.

Each finding includes a severity level and actionable remediation guidance.`,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		logging.Init(verbose)
		loaded, err := config.Load(".")
		if err != nil {
			slog.Warn("Failed to load config file", "error", err)
		} else {
			cfg = loaded
		}
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command with injected build info.
func Execute(v, c, d string) error {
	version = v
	commit = c
	date = d
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	rootCmd.PersistentFlags().StringVar(&context_, "context", "", "Kubernetes context to use")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Namespace to audit (default: all)")
	rootCmd.AddCommand(versionCmd)
}
