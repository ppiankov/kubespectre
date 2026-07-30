package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// WO-40: Released + Retain + past stale_days must be flagged, with CSI evidence in metadata.
func TestPersistentVolumeScanner_StaleReleasedVolume(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "old-released-pv",
			CreationTimestamp: staleTime,
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			StorageClassName:              "gp3",
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{Driver: "ebs.csi.aws.com", VolumeHandle: "vol-abc123"},
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	})

	scanner := &PersistentVolumeScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.ID != FindingStaleReleasedVolume {
		t.Errorf("finding ID = %q, want %q", f.ID, FindingStaleReleasedVolume)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityMedium)
	}
	if f.Metadata["csi_driver"] != "ebs.csi.aws.com" || f.Metadata["volume_handle"] != "vol-abc123" {
		t.Errorf("metadata missing CSI evidence: %+v", f.Metadata)
	}
}

// WO-40: a Released volume younger than stale_days must not be flagged.
func TestPersistentVolumeScanner_YoungReleasedVolumeNotFlagged(t *testing.T) {
	recentTime := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "young-released-pv", CreationTimestamp: recentTime},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	})

	scanner := &PersistentVolumeScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

// WO-40: reclaimPolicy=Delete must never be flagged regardless of age.
func TestPersistentVolumeScanner_DeleteReclaimPolicyNotFlagged(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "delete-policy-pv", CreationTimestamp: staleTime},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	})

	scanner := &PersistentVolumeScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

// WO-40: only phase=Released is in scope; Bound must never be flagged.
func TestPersistentVolumeScanner_BoundVolumeNotFlagged(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "bound-pv", CreationTimestamp: staleTime},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	})

	scanner := &PersistentVolumeScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

// WO-40: status.lastPhaseTransitionTime must take precedence over creationTimestamp
// when computing staleness -- confirmed against real cluster data where every
// currently-Released PV had a far more recent transition time than creation time.
func TestPersistentVolumeScanner_LastPhaseTransitionTimeTakesPrecedence(t *testing.T) {
	oldCreation := metav1.NewTime(time.Now().AddDate(0, 0, -200))
	recentTransition := metav1.NewTime(time.Now().AddDate(0, 0, -1))
	client := fake.NewSimpleClientset(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "recently-released-pv", CreationTimestamp: oldCreation},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
		},
		Status: corev1.PersistentVolumeStatus{
			Phase:                   corev1.VolumeReleased,
			LastPhaseTransitionTime: &recentTransition,
		},
	})

	scanner := &PersistentVolumeScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (creation is old but the release transition is recent)", len(findings))
	}
}

// WO-40: an excluded PV must produce neither a finding nor a scanned-count increment.
func TestPersistentVolumeScanner_ExcludedByLabel(t *testing.T) {
	staleTime := metav1.NewTime(time.Now().AddDate(0, 0, -100))
	client := fake.NewSimpleClientset(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "excluded-pv",
			CreationTimestamp: staleTime,
			Labels:            map[string]string{"tier": "legacy"},
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	})

	exclusions, err := NewExclusions(nil, []string{"tier=legacy"})
	if err != nil {
		t.Fatalf("NewExclusions: %v", err)
	}

	scanner := &PersistentVolumeScanner{}
	findings, scanned, err := scanner.auditWithCount(context.Background(), client, AuditConfig{Cluster: "test", StaleDays: 90, Exclusions: exclusions})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (excluded)", len(findings))
	}
	if scanned != 0 {
		t.Fatalf("scanned = %d, want 0 (excluded volume must not count as scanned)", scanned)
	}
}
