package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool { return &b }

func TestPodSecurityScanner_Privileged(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:            "app",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					},
				},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingPrivilegedContainer {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingPrivilegedContainer)
	}
}

func TestPodSecurityScanner_HostNetwork(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "net-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers: []corev1.Container{{
					Name:            "app",
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)},
				}},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingHostNetwork {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingHostNetwork)
	}
}

func TestPodSecurityScanner_HostPID(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pid-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostPID: true,
				Containers: []corev1.Container{{
					Name:            "app",
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)},
				}},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingHostPID {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingHostPID)
	}
}

func TestPodSecurityScanner_MultipleViolations(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				HostPID:     true,
				Containers: []corev1.Container{
					{
						Name:            "main",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:            "init",
						SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
					},
				},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// hostNetwork + hostPID + 2 privileged containers = 4
	if len(findings) != 4 {
		t.Errorf("got %d findings, want 4", len(findings))
	}
}

func TestPodSecurityScanner_Clean(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							Privileged:               boolPtr(false),
							AllowPrivilegeEscalation: boolPtr(false),
						},
					},
				},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestPodSecurityScanner_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "prod"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)}},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "other-pod", Namespace: "staging"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers:  []corev1.Container{{Name: "app"}},
			},
		},
	)

	scanner := &PodSecurityScanner{}
	findings, err := scanner.Audit(context.Background(), client, AuditConfig{Cluster: "test", Namespace: "prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1 (only prod namespace)", len(findings))
	}
}

// WO-21: Exclude matching pods without suppressing neighboring violations.
func TestPodSecurityScanner_Exclusions(t *testing.T) {
	exclusions, err := NewExclusions([]string{"excluded"}, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	noEscalation := []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)}}}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "namespace-skip", Namespace: "excluded"}, Spec: corev1.PodSpec{HostNetwork: true, Containers: noEscalation}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "label-skip", Namespace: "default", Labels: map[string]string{"scan": "skip"}}, Spec: corev1.PodSpec{HostNetwork: true, Containers: noEscalation}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "default"}, Spec: corev1.PodSpec{HostNetwork: true, Containers: noEscalation}},
	)

	findings, err := (&PodSecurityScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:    "test",
		Exclusions: exclusions,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ResourceID != "keep" {
		t.Fatalf("findings = %#v, want only neighboring pod", findings)
	}
}

// WO-33: the scanned count must reflect only pods that survive exclusion
// filtering, not every pod listed.
func TestPodSecurityScanner_CountsOnlyEvaluatedPods(t *testing.T) {
	exclusions, err := NewExclusions([]string{"excluded"}, []string{"scan=skip"})
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "namespace-skip", Namespace: "excluded"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "label-skip", Namespace: "default", Labels: map[string]string{"scan": "skip"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "default"}},
	)

	_, scanned, err := (&PodSecurityScanner{}).auditWithCount(context.Background(), client, AuditConfig{Cluster: "test", Exclusions: exclusions})
	if err != nil {
		t.Fatalf("auditWithCount() error = %v", err)
	}
	if scanned != 1 {
		t.Fatalf("scanned = %d, want 1 (only the evaluated pod, not the 3 listed)", scanned)
	}
}

// WO-35: a hostPath volume must be flagged; a pod with no hostPath volumes must not.
func TestPodSecurityScanner_HostPathVolume(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "hostpath-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "app",
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)},
				}},
				Volumes: []corev1.Volume{
					{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/data"}}},
					{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
				},
			},
		},
	)

	findings, err := (&PodSecurityScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != FindingHostPathVolume {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingHostPathVolume)
	}
	if findings[0].Metadata["path"] != "/var/lib/data" {
		t.Errorf("metadata path = %v, want /var/lib/data", findings[0].Metadata["path"])
	}
}

// WO-35: a container adding a dangerous capability must be flagged, naming the
// capability; a container that adds no capabilities must not.
func TestPodSecurityScanner_DangerousCapability(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "cap-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "risky",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: boolPtr(false),
							Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "CHOWN"}},
						},
					},
					{
						Name: "safe",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: boolPtr(false),
							Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"CHOWN"}},
						},
					},
				},
			},
		},
	)

	findings, err := (&PodSecurityScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only the NET_ADMIN container)", len(findings))
	}
	if findings[0].ID != FindingDangerousCapability {
		t.Errorf("finding ID = %q, want %q", findings[0].ID, FindingDangerousCapability)
	}
	if findings[0].Metadata["container"] != "risky" {
		t.Errorf("container = %v, want risky", findings[0].Metadata["container"])
	}
}

// WO-35: DangerousCapabilities overrides the built-in default list when configured.
func TestPodSecurityScanner_DangerousCapabilityConfigured(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "cap-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolPtr(false),
						Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"CHOWN"}},
					},
				}},
			},
		},
	)

	findings, err := (&PodSecurityScanner{}).Audit(context.Background(), client, AuditConfig{
		Cluster:               "test",
		DangerousCapabilities: []string{"CHOWN"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != FindingDangerousCapability {
		t.Fatalf("findings = %#v, want 1 DANGEROUS_CAPABILITY (CHOWN configured)", findings)
	}
}

// WO-35: a container that does not set allowPrivilegeEscalation to false must be
// flagged; a container that explicitly sets it false must not. A privileged
// container is exempt (already flagged as PRIVILEGED_CONTAINER).
func TestPodSecurityScanner_PrivilegeEscalation(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "unset"},
					{Name: "explicit-true", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(true)}},
					{Name: "hardened", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)}},
					{
						Name: "privileged-exempt",
						SecurityContext: &corev1.SecurityContext{
							Privileged: boolPtr(true),
						},
					},
				},
			},
		},
	)

	findings, err := (&PodSecurityScanner{}).Audit(context.Background(), client, AuditConfig{Cluster: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "unset" + "explicit-true" flagged for escalation; "privileged-exempt" flagged
	// as PRIVILEGED_CONTAINER only (not double-flagged for escalation); "hardened" clean.
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %#v", len(findings), findings)
	}
	escalationCount, privilegedCount := 0, 0
	for _, f := range findings {
		switch f.ID {
		case FindingPrivilegeEscalation:
			escalationCount++
		case FindingPrivilegedContainer:
			privilegedCount++
		default:
			t.Errorf("unexpected finding ID %q", f.ID)
		}
	}
	if escalationCount != 2 || privilegedCount != 1 {
		t.Fatalf("escalation=%d privileged=%d, want 2 and 1", escalationCount, privilegedCount)
	}
}
