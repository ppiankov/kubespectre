package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
)

// Auditor is the interface each resource-type auditor implements.
type Auditor interface {
	Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error)
	Name() string
}

// WO-6: evidenceAuditor keeps the positive evidence plane opt-in for compatible auditors.
type evidenceAuditor interface {
	auditWithEvidence(
		ctx context.Context,
		client kubernetes.Interface,
		cfg AuditConfig,
	) (*serviceAccountEvidenceResult, error)
}

// WO-25: countingAuditor lets an auditor report how many primary cluster objects
// it enumerated, so AuditAll can populate ScanResult.ResourcesScanned instead of
// leaving total_resources_scanned pinned at zero. The count is the number of
// objects an auditor lists to drive its findings; an object examined by several
// auditors contributes once per auditor.
type countingAuditor interface {
	auditWithCount(
		ctx context.Context,
		client kubernetes.Interface,
		cfg AuditConfig,
	) ([]Finding, int, error)
}

// MultiAuditor orchestrates running multiple auditors in parallel.
type MultiAuditor struct {
	client      kubernetes.Interface
	auditors    []Auditor
	concurrency int
}

// NewMultiAuditor creates an auditor that runs the specified auditors in parallel.
func NewMultiAuditor(client kubernetes.Interface, auditors []Auditor, concurrency int) *MultiAuditor {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &MultiAuditor{
		client:      client,
		auditors:    auditors,
		concurrency: concurrency,
	}
}

// AuditAll runs all auditors and returns combined results.
// WO-6: Merge positive evidence and proven coverage without changing auditor concurrency.
func (m *MultiAuditor) AuditAll(ctx context.Context, cfg AuditConfig) (*ScanResult, error) {
	var (
		mu       sync.Mutex
		combined ScanResult
	)

	// WO-42@v2: keep gctx scoped to the auditor fan-out only -- errgroup cancels
	// its derived context the instant Wait returns (even on success), so the
	// networking-observation call after g.Wait() below must use the original,
	// still-live ctx parameter, never this one.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(m.concurrency)

	for _, auditor := range m.auditors {
		a := auditor
		g.Go(func() error {
			slog.Debug("Running auditor", "name", a.Name())

			var (
				findings         []Finding
				positiveEdges    []ClusterPositiveEdge
				coverage         []NamespaceCoverage
				auditErrors      []string
				resourcesScanned int // WO-25: primary objects this auditor enumerated.
			)
			switch source := a.(type) {
			case evidenceAuditor:
				// WO-6: merge only evidence returned by the sealed ServiceAccount collection path.
				result, err := source.auditWithEvidence(gctx, m.client, cfg)
				if err != nil {
					mu.Lock()
					combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", a.Name(), err))
					mu.Unlock()
					slog.Warn("Auditor failed", "name", a.Name(), "error", err)
					return nil
				}
				findings = result.Findings
				positiveEdges = result.ClusterPositiveEdges
				coverage = result.Coverage
				auditErrors = result.Errors
				resourcesScanned = result.ResourcesScanned // WO-25: count evidence-path objects.
			case countingAuditor:
				// WO-25: prefer the counting variant so the auditor reports scanned objects.
				var err error
				findings, resourcesScanned, err = source.auditWithCount(gctx, m.client, cfg)
				if err != nil {
					mu.Lock()
					combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", a.Name(), err))
					mu.Unlock()
					slog.Warn("Auditor failed", "name", a.Name(), "error", err)
					return nil
				}
			default:
				var err error
				findings, err = a.Audit(gctx, m.client, cfg)
				if err != nil {
					mu.Lock()
					combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", a.Name(), err))
					mu.Unlock()
					slog.Warn("Auditor failed", "name", a.Name(), "error", err)
					return nil
				}
			}

			mu.Lock()
			combined.Findings = append(combined.Findings, findings...)
			// WO-6: merge positive evidence, proven scope, and collection errors atomically.
			combined.ClusterPositiveEdges = append(combined.ClusterPositiveEdges, positiveEdges...)
			combined.NamespaceCoverage = append(combined.NamespaceCoverage, coverage...)
			combined.ResourcesScanned += resourcesScanned // WO-25: sum scanned objects across auditors.
			for _, auditErr := range auditErrors {
				combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %s", a.Name(), auditErr))
			}
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// WO-42@v2: networking-component observations are collected OUTSIDE the
	// Auditor/Finding dispatch loop above -- this is the structural guarantee
	// behind the strong separation invariant: this call cannot alter
	// combined.Findings because it never participates in that loop at all.
	observations := ObserveNetworkingComponents(ctx, m.client)
	combined.EnvironmentObservations = &EnvironmentObservations{Networking: observations}

	return &combined, nil
}

// AllAuditors returns the full set of security auditors.
func AllAuditors() []Auditor {
	return []Auditor{
		&RBACScanner{},
		&PodSecurityScanner{},
		&NetworkPolicyScanner{},
		&SecretScanner{},
		&ServiceAccountScanner{},
		&ImageScanner{},
		&AuditLogScanner{},
		&PersistentVolumeScanner{}, // WO-40: stale Released-phase volume retention.
	}
}

// RBACOnlyAuditors returns just the RBAC auditor.
func RBACOnlyAuditors() []Auditor {
	return []Auditor{
		&RBACScanner{},
	}
}
