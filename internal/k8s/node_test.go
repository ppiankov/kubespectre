package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

// WO-47: test helper to control the fake client's reported API server version.
func setServerVersion(t *testing.T, client *fake.Clientset, gitVersion string) {
	t.Helper()
	fd, ok := client.Discovery().(*fakediscovery.FakeDiscovery)
	if !ok {
		t.Fatal("client.Discovery() is not *fakediscovery.FakeDiscovery")
	}
	fd.FakedServerVersion = &version.Info{GitVersion: gitVersion}
}

// WO-47: DiskPressure=True is a genuine, currently-active problem confirmed
// live on the real research cluster -- must be flagged.
func TestNodeScanner_DiskPressureFlagged(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fargate-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue},
				{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
			},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.6-eks-bca9cf6"},
		},
	})
	setServerVersion(t, client, "v1.35.6-eks-8f14419")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (DiskPressure only)", len(findings))
	}
	if findings[0].ID != FindingNodeConditionDegraded {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingNodeConditionDegraded)
	}
	if findings[0].Metadata["condition_type"] != "DiskPressure" {
		t.Errorf("metadata condition_type = %v, want DiskPressure", findings[0].Metadata["condition_type"])
	}
}

// WO-47: Ready=False must be flagged distinctly.
func TestNodeScanner_NotReadyFlagged(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "down-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
			},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.6"},
		},
	})
	setServerVersion(t, client, "v1.35.6")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingNodeConditionDegraded {
		t.Fatalf("findings = %+v, want exactly one NODE_CONDITION_DEGRADED", findings)
	}
}

// WO-47: the caught false-positive -- EKS Auto Mode nodes report additional
// condition types (NetworkingReady, KernelReady, StorageReady,
// ContainerRuntimeReady, AcceleratedHardwareReady) where True means
// healthy, the OPPOSITE polarity from the four standard problem conditions.
// A closed allowlist must never flag these; this pins the exact regression
// a blanket "non-Ready condition True" rule would have produced.
func TestNodeScanner_EKSAutoModeConditionsNotFlagged(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "auto-mode-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
				{Type: "NetworkingReady", Status: corev1.ConditionTrue},
				{Type: "KernelReady", Status: corev1.ConditionTrue},
				{Type: "StorageReady", Status: corev1.ConditionTrue},
				{Type: "ContainerRuntimeReady", Status: corev1.ConditionTrue},
				{Type: "AcceleratedHardwareReady", Status: corev1.ConditionTrue},
			},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.5-eks-a3a0722"},
		},
	})
	setServerVersion(t, client, "v1.35.5-eks-a3a0722")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 -- EKS Auto Mode *Ready=True conditions must never be flagged: %+v", len(findings), findings)
	}
}

// WO-47: a healthy node with only standard conditions produces no finding.
func TestNodeScanner_HealthyNodeClean(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionFalse},
			},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.6"},
		},
	})
	setServerVersion(t, client, "v1.35.6")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

// WO-47: kubelet older than the API server (patch-level skew, confirmed live
// on the research cluster: 4 simultaneous kubelet versions) must be flagged.
func TestNodeScanner_KubeletVersionOutdated(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "old-kubelet-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.35.0-eks-ac2d5a0"},
		},
	})
	setServerVersion(t, client, "v1.35.6-eks-8f14419")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingNodeKubeletVersionOutdated {
		t.Fatalf("findings = %+v, want exactly one NODE_KUBELET_VERSION_OUTDATED", findings)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("severity = %q, want low (informational)", findings[0].Severity)
	}
}

// WO-47: a semver-aware comparison is required -- v1.35.6 must not sort
// after v1.35.10 as a naive string comparison would (lexically "6" > "1").
func TestNodeScanner_KubeletVersionComparisonIsSemverAware(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.35.9"},
		},
	})
	setServerVersion(t, client, "v1.35.10")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingNodeKubeletVersionOutdated {
		t.Fatalf("v1.35.9 vs v1.35.10: findings = %+v, want exactly one NODE_KUBELET_VERSION_OUTDATED (numeric 9 < 10)", findings)
	}
}

// WO-47: kubelet at or ahead of the server version produces no finding.
func TestNodeScanner_KubeletVersionCurrent(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.35.6"},
		},
	})
	setServerVersion(t, client, "v1.35.6")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

// WO-47: a minor-version gap exceeding the documented 3-minor skew policy is
// called out explicitly; a smaller gap is reported without that claim.
func TestNodeScanner_MinorVersionSkewPolicyWording(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "very-old-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.30.0"},
		},
	})
	setServerVersion(t, client, "v1.35.0")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if want := "exceeding the documented 3-minor-version skew policy"; !contains(findings[0].Message, want) {
		t.Errorf("message = %q, want it to mention %q for a 5-minor-version gap", findings[0].Message, want)
	}
}

// WO-47: substring test helper for the skew-policy-wording assertion.
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// WO-47: exclusions must apply before both checks, and the scanned count
// must reflect only evaluated (non-excluded) nodes.
func TestNodeScanner_Exclusions(t *testing.T) {
	exclusions, err := NewExclusions(nil, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "skip-node", Labels: map[string]string{"scan": "skip"}},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue}},
				NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.30.0"},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "keep-node"},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.35.6"},
			},
		},
	)
	setServerVersion(t, client, "v1.35.6")

	findings, scanned, err := (&NodeScanner{}).auditWithCount(context.Background(), client, AuditConfig{Cluster: "test", Exclusions: exclusions})
	if err != nil {
		t.Fatalf("auditWithCount() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (skip-node's problems must be excluded)", len(findings))
	}
	if scanned != 1 {
		t.Fatalf("scanned = %d, want 1 (only keep-node evaluated)", scanned)
	}
}

// WO-47: an unparseable kubelet or server version must never be guessed --
// no finding, no crash.
func TestNodeScanner_UnparseableVersionsProduceNoFinding(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "weird-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "not-a-version"},
		},
	})
	setServerVersion(t, client, "v1.35.6")

	findings, err := (&NodeScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 for an unparseable kubelet version", len(findings))
	}
}
