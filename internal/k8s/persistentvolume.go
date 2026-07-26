package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PersistentVolumeScanner audits PersistentVolumes for stale data retention.
// WO-40: a PV with reclaimPolicy=Retain whose bound PVC/namespace has been
// deleted enters phase=Released: the underlying cloud volume is NOT deleted
// and can still contain the workload's data, but the PV object lingers
// unbound and unmanaged.
type PersistentVolumeScanner struct{}

// WO-40: registers this auditor's identity for MultiAuditor dispatch.
func (s *PersistentVolumeScanner) Name() string { return "persistentvolume" }

// WO-40: posture-only entry point; delegates to the counting variant.
func (s *PersistentVolumeScanner) Audit(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, error) {
	findings, _, err := s.auditWithCount(ctx, client, cfg)
	return findings, err
}

// WO-40: auditWithCount reports the PersistentVolumes examined for retention posture.
func (s *PersistentVolumeScanner) auditWithCount(ctx context.Context, client kubernetes.Interface, cfg AuditConfig) ([]Finding, int, error) {
	var findings []Finding

	pvs, err := client.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list persistentvolumes: %w", err)
	}

	staleDays := cfg.StaleDays
	if staleDays <= 0 {
		staleDays = 90
	}
	staleThreshold := time.Now().AddDate(0, 0, -staleDays)

	scanned := 0
	for _, pv := range pvs.Items {
		// WO-40: PersistentVolume is cluster-scoped; mirror the "" namespace
		// convention already used for ClusterRole/ClusterRoleBinding exclusion.
		if cfg.Exclusions.Matches("", pv.Labels) {
			continue
		}
		scanned++

		if pv.Status.Phase != corev1.VolumeReleased {
			continue
		}
		if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
			continue
		}

		since := pv.CreationTimestamp.Time
		if pv.Status.LastPhaseTransitionTime != nil {
			since = pv.Status.LastPhaseTransitionTime.Time
		}
		if since.After(staleThreshold) {
			continue
		}

		metadata := map[string]any{
			"reclaim_policy": string(pv.Spec.PersistentVolumeReclaimPolicy),
			"storage_class":  pv.Spec.StorageClassName,
		}
		if capacity, ok := pv.Spec.Capacity["storage"]; ok {
			metadata["capacity"] = capacity.String()
		}
		if pv.Spec.CSI != nil {
			metadata["csi_driver"] = pv.Spec.CSI.Driver
			metadata["volume_handle"] = pv.Spec.CSI.VolumeHandle
		}

		findings = append(findings, Finding{
			ID:           FindingStaleReleasedVolume,
			Severity:     SeverityMedium,
			ResourceType: "PersistentVolume",
			ResourceID:   pv.Name,
			Cluster:      cfg.Cluster,
			Message:      fmt.Sprintf("PersistentVolume released %d+ days ago with reclaimPolicy=Retain -- the underlying cloud volume is not deleted and may still hold the former workload's data", staleDays),
			Metadata:     metadata,
		})
	}

	return findings, scanned, nil
}
