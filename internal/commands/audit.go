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
)

var auditFlags struct {
	format      string
	outputFile  string
	severityMin string
	staleDays   int
	timeout     time.Duration
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

func init() {
	auditCmd.Flags().StringVar(&auditFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	auditCmd.Flags().StringVarP(&auditFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	auditCmd.Flags().StringVar(&auditFlags.severityMin, "severity-min", "low", "Minimum severity: critical, high, medium, low")
	auditCmd.Flags().IntVar(&auditFlags.staleDays, "stale-days", 90, "Threshold for stale secrets (days)")
	auditCmd.Flags().DurationVar(&auditFlags.timeout, "timeout", 5*time.Minute, "Audit timeout")

	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, _ []string) error {
	return runAuditWithAuditors(cmd, k8s.AllAuditors())
}

func runAuditWithAuditors(cmd *cobra.Command, auditors []k8s.Auditor) error {
	ctx := cmd.Context()
	if auditFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, auditFlags.timeout)
		defer cancel()
	}

	applyConfigDefaults()

	client, err := k8s.BuildClient(k8s.KubeOpts{
		Kubeconfig: kubeconfig,
		Context:    context_,
	})
	if err != nil {
		return enhanceError("connect to cluster", err)
	}

	ns := namespace
	if ns == "" && cfg.Namespace != "" {
		ns = cfg.Namespace
	}

	severityMin := k8s.ParseSeverity(auditFlags.severityMin)

	auditCfg := k8s.AuditConfig{
		Namespace:         ns,
		StaleDays:         auditFlags.staleDays,
		SeverityMin:       severityMin,
		TrustedRegistries: cfg.TrustedRegistries,
		Cluster:           resolveClusterName(),
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
			Namespace:   ns,
			StaleDays:   auditFlags.staleDays,
			SeverityMin: auditFlags.severityMin,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
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

func applyConfigDefaults() {
	if auditFlags.format == "text" && cfg.Format != "" {
		auditFlags.format = cfg.Format
	}
	if auditFlags.staleDays == 90 && cfg.StaleDays > 0 {
		auditFlags.staleDays = cfg.StaleDays
	}
	if auditFlags.severityMin == "low" && cfg.SeverityMin != "" {
		auditFlags.severityMin = cfg.SeverityMin
	}
}
