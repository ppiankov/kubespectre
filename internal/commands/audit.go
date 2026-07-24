package commands

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/kubespectre/internal/analyzer"
	"github.com/ppiankov/kubespectre/internal/k8s"
	"github.com/ppiankov/kubespectre/internal/report"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// WO-18: Name shared audit defaults so registration and precedence cannot drift.
const (
	defaultAuditFormat  = "text"
	defaultSeverityMin  = "low"
	defaultStaleDays    = 90
	defaultAuditTimeout = 5 * time.Minute
)

var auditFlags struct {
	format      string
	outputFile  string
	severityMin string
	staleDays   int
	timeout     time.Duration
	joinKeys    bool
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run full security posture audit",
	Long: `Audit a Kubernetes cluster for security posture issues: RBAC misconfigurations,
pod security violations, missing network policies, secret lifecycle issues,
service account hygiene, image provenance, and audit logging.

Requires a valid kubeconfig with read access to cluster resources.`,
	RunE: runAudit,
}

// WO-18: Install one shared audit flag surface before registering the command.
func init() {
	addAuditFlags(auditCmd, true)

	rootCmd.AddCommand(auditCmd)
}

// WO-18: Register the shared audit surface once for audit and RBAC commands.
func addAuditFlags(cmd *cobra.Command, includeStaleDays bool) {
	cmd.Flags().StringVar(&auditFlags.format, "format", defaultAuditFormat, "Output format: text, json, sarif, spectrehub")
	cmd.Flags().StringVarP(&auditFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&auditFlags.severityMin, "severity-min", defaultSeverityMin, "Minimum severity: critical, high, medium, low")
	cmd.Flags().DurationVar(&auditFlags.timeout, "timeout", defaultAuditTimeout, "Audit timeout")
	cmd.Flags().BoolVar(&auditFlags.joinKeys, "include-edge-join-keys", false, "Include join keys in cluster_positive_edges output")
	if includeStaleDays {
		cmd.Flags().IntVar(&auditFlags.staleDays, "stale-days", defaultStaleDays, "Threshold for stale secrets (days)")
	}
}

func runAudit(cmd *cobra.Command, _ []string) error {
	return runAuditWithAuditors(cmd, k8s.AllAuditors())
}

// WO-15: Preserve positive cluster evidence through user-facing report envelopes.
// WO-18: Resolve configuration before constructing the command deadline.
func runAuditWithAuditors(cmd *cobra.Command, auditors []k8s.Auditor) error {
	if err := applyConfigDefaults(cmd); err != nil {
		return err
	}
	exclusions, err := configuredExclusions()
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	if auditFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, auditFlags.timeout)
		defer cancel()
	}

	client, err := k8s.BuildClient(k8s.KubeOpts{
		Kubeconfig: kubeconfig,
		Context:    context_,
	})
	if err != nil {
		return enhanceError("connect to cluster", err)
	}

	ns := effectiveNamespace(cmd)

	severityMin := k8s.ParseSeverity(auditFlags.severityMin)

	auditCfg := k8s.AuditConfig{
		Namespace:         ns,
		StaleDays:         auditFlags.staleDays,
		SeverityMin:       severityMin,
		TrustedRegistries: cfg.TrustedRegistries,
		Cluster:           resolveClusterName(),
		Exclusions:        exclusions, // WO-20: carry the validated operator scan boundary.
	}

	slog.Info("Starting audit", "namespace", ns, "severity-min", auditFlags.severityMin)

	multi := k8s.NewMultiAuditor(client, auditors, 4)
	result, err := multi.AuditAll(ctx, auditCfg)
	if err != nil {
		return enhanceError("audit cluster", err)
	}

	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		SeverityMin: severityMin,
	})

	data := report.Data{
		Tool:      "kubespectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "kubernetes",
			URIHash: computeTargetHash(auditCfg.Cluster, ns),
		},
		Config: report.ReportConfig{
			Namespace:                          ns,
			StaleDays:                          auditFlags.staleDays,
			SeverityMin:                        auditFlags.severityMin,
			IncludeClusterPositiveEdgeJoinKeys: auditFlags.joinKeys,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
		ClusterPositiveEdges: k8s.ProjectClusterPositiveEdges( // WO-24: project edge records for reporting.
			result.ClusterPositiveEdges,
			auditFlags.joinKeys,
		),
		NamespaceCoverage: result.NamespaceCoverage, // WO-15: retain proven scope for artifact consumers.
	}

	reporter, err := selectReporter(auditFlags.format, auditFlags.outputFile)
	if err != nil {
		return err
	}

	if err := reporter.Generate(data); err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	if analysis.Summary.TotalFindings > 0 {
		slog.Info("Audit complete", "findings", analysis.Summary.TotalFindings)
	}

	return nil
}

func resolveClusterName() string {
	if context_ != "" {
		return context_
	}
	return "current-context"
}

// WO-18: Apply configuration only where Cobra proves the operator omitted a flag.
func applyConfigDefaults(cmd *cobra.Command) error {
	if !commandFlagChanged(cmd, "format") && cfg.Format != "" {
		auditFlags.format = cfg.Format
	}
	if commandHasFlag(cmd, "stale-days") && !commandFlagChanged(cmd, "stale-days") && cfg.StaleDays > 0 {
		auditFlags.staleDays = cfg.StaleDays
	}
	if !commandFlagChanged(cmd, "severity-min") && cfg.SeverityMin != "" {
		auditFlags.severityMin = cfg.SeverityMin
	}
	if !commandFlagChanged(cmd, "timeout") && cfg.Timeout != "" {
		timeout, err := cfg.TimeoutDuration()
		if err != nil {
			return fmt.Errorf("configured timeout: %w", err)
		}
		auditFlags.timeout = timeout
	}
	return nil
}

// WO-18: Preserve an explicit empty namespace as the all-namespaces choice.
func effectiveNamespace(cmd *cobra.Command) string {
	if !commandFlagChanged(cmd, "namespace") && cfg.Namespace != "" {
		return cfg.Namespace
	}
	return namespace
}

// WO-18: Inspect local and inherited Cobra flag sets without value sentinels.
func commandFlagChanged(cmd *cobra.Command, name string) bool {
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.InheritedFlags(), cmd.PersistentFlags()} {
		if flag := flags.Lookup(name); flag != nil && flag.Changed {
			return true
		}
	}
	return false
}

// WO-18: Keep command-specific configuration away from flags the command does not expose.
func commandHasFlag(cmd *cobra.Command, name string) bool {
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.InheritedFlags(), cmd.PersistentFlags()} {
		if flags.Lookup(name) != nil {
			return true
		}
	}
	return false
}

// WO-20: Validate configured exclusions before Kubernetes client or scanner work.
func configuredExclusions() (k8s.Exclusions, error) {
	exclusions, err := k8s.NewExclusions(cfg.Exclude.Namespaces, cfg.Exclude.Labels)
	if err != nil {
		return k8s.Exclusions{}, fmt.Errorf("configured exclusions: %w", err)
	}
	return exclusions, nil
}
