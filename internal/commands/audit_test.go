package commands

import (
	"testing"
	"time"

	"github.com/ppiankov/kubespectre/internal/config"
	"github.com/spf13/cobra"
)

// WO-18: Prove explicit default-valued flags still override configuration.
func TestApplyConfigDefaultsHonorsChangedFlags(t *testing.T) {
	cmd := newAuditOptionsTestCommand(t)
	cfg = config.Config{
		Namespace:   "configured",
		StaleDays:   120,
		SeverityMin: "critical",
		Format:      "json",
		Timeout:     "10m",
	}

	setFlag(t, cmd, "format", defaultAuditFormat)
	setFlag(t, cmd, "severity-min", defaultSeverityMin)
	setFlag(t, cmd, "stale-days", "90")
	setFlag(t, cmd, "timeout", defaultAuditTimeout.String())
	setFlag(t, cmd, "namespace", "")

	if err := applyConfigDefaults(cmd); err != nil {
		t.Fatalf("applyConfigDefaults() error = %v", err)
	}
	if auditFlags.format != defaultAuditFormat ||
		auditFlags.severityMin != defaultSeverityMin ||
		auditFlags.staleDays != defaultStaleDays ||
		auditFlags.timeout != defaultAuditTimeout {
		t.Fatalf("explicit defaults overwritten: %#v", auditFlags)
	}
	if got := effectiveNamespace(cmd); got != "" {
		t.Fatalf("effectiveNamespace() = %q, want explicit all-namespaces value", got)
	}
}

// WO-18: Prove unchanged flags inherit every supported configuration default.
func TestApplyConfigDefaultsUsesConfiguration(t *testing.T) {
	cmd := newAuditOptionsTestCommand(t)
	cfg = config.Config{
		Namespace:   "configured",
		StaleDays:   120,
		SeverityMin: "critical",
		Format:      "json",
		Timeout:     "10m",
	}

	if err := applyConfigDefaults(cmd); err != nil {
		t.Fatalf("applyConfigDefaults() error = %v", err)
	}
	if auditFlags.format != "json" ||
		auditFlags.severityMin != "critical" ||
		auditFlags.staleDays != 120 ||
		auditFlags.timeout != 10*time.Minute {
		t.Fatalf("configuration defaults not applied: %#v", auditFlags)
	}
	if got := effectiveNamespace(cmd); got != "configured" {
		t.Fatalf("effectiveNamespace() = %q, want configured", got)
	}
}

// WO-18: Reject malformed configured timeouts instead of disabling the deadline.
func TestApplyConfigDefaultsRejectsInvalidTimeout(t *testing.T) {
	cmd := newAuditOptionsTestCommand(t)
	cfg = config.Config{Timeout: "eventually"}

	if err := applyConfigDefaults(cmd); err == nil {
		t.Fatal("applyConfigDefaults() error = nil, want invalid timeout error")
	}
	if auditFlags.timeout != defaultAuditTimeout {
		t.Fatalf("timeout = %v, want preserved default %v", auditFlags.timeout, defaultAuditTimeout)
	}
}

// WO-20: Propagate configured namespace and label boundaries into scanner policy.
func TestConfiguredExclusions(t *testing.T) {
	cfg = config.Config{Exclude: config.Exclude{
		Namespaces: []string{"kube-system"},
		Labels:     []string{"app=legacy"},
	}}

	exclusions, err := configuredExclusions()
	if err != nil {
		t.Fatalf("configuredExclusions() error = %v", err)
	}
	if !exclusions.Matches("kube-system", nil) {
		t.Error("configured namespace was not excluded")
	}
	if !exclusions.Matches("default", map[string]string{"app": "legacy"}) {
		t.Error("configured label was not excluded")
	}
	if exclusions.Matches("default", map[string]string{"app": "api"}) {
		t.Error("neighboring resource was excluded")
	}
}

// WO-20: Reject invalid configured selectors before any scanner can run.
func TestConfiguredExclusionsRejectsInvalidSelector(t *testing.T) {
	cfg = config.Config{Exclude: config.Exclude{Labels: []string{"app in ("}}}
	if _, err := configuredExclusions(); err == nil {
		t.Fatal("configuredExclusions() error = nil, want invalid selector error")
	}
}

// WO-18: Build an isolated Cobra surface around the shared option resolver.
func newAuditOptionsTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	auditFlags = struct {
		format      string
		outputFile  string
		severityMin string
		staleDays   int
		timeout     time.Duration
	}{}
	namespace = ""
	cfg = config.Config{}

	cmd := &cobra.Command{Use: "audit-test"}
	addAuditFlags(cmd, true)
	cmd.Flags().StringVar(&namespace, "namespace", "", "test namespace")
	return cmd
}

// WO-18: Mark flags changed through Cobra's public API in precedence tests.
func setFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set %s: %v", name, err)
	}
}
