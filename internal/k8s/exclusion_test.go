package k8s

import "testing"

// WO-19: Pin exact namespace and Kubernetes label-selector exclusion semantics.
func TestExclusionsMatchNamespaceOrLabels(t *testing.T) {
	exclusions, err := NewExclusions(
		[]string{"kube-system"},
		[]string{"app=legacy", "tier in (internal,batch)"},
	)
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}

	tests := []struct {
		name      string
		namespace string
		labels    map[string]string
		want      bool
	}{
		{name: "namespace", namespace: "kube-system", want: true},
		{name: "exact label", namespace: "default", labels: map[string]string{"app": "legacy"}, want: true},
		{name: "set label", namespace: "default", labels: map[string]string{"tier": "batch"}, want: true},
		{name: "neighbor", namespace: "default", labels: map[string]string{"app": "api"}, want: false},
		{name: "nil labels", namespace: "default", labels: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exclusions.Matches(tt.namespace, tt.labels); got != tt.want {
				t.Errorf("Matches(%q, %#v) = %t, want %t", tt.namespace, tt.labels, got, tt.want)
			}
		})
	}
}

// WO-19: Keep malformed selectors fail-closed at configuration construction.
func TestNewExclusionsRejectsInvalidSelector(t *testing.T) {
	if _, err := NewExclusions(nil, []string{"app in ("}); err == nil {
		t.Fatal("NewExclusions() error = nil, want invalid selector error")
	}
}

// WO-19: Prove empty policy and caller mutation cannot widen runtime exclusions.
func TestExclusionsZeroValueAndInputIsolation(t *testing.T) {
	var zero Exclusions
	if zero.Matches("kube-system", map[string]string{"app": "legacy"}) {
		t.Fatal("zero-value exclusions matched a resource")
	}

	namespaces := []string{"private"}
	selectors := []string{"app=legacy"}
	exclusions, err := NewExclusions(namespaces, selectors)
	if err != nil {
		t.Fatalf("NewExclusions() error = %v", err)
	}
	namespaces[0] = "default"
	selectors[0] = "app=api"

	if !exclusions.Matches("private", nil) {
		t.Error("namespace input mutation changed constructed exclusions")
	}
	if exclusions.Matches("default", nil) {
		t.Error("namespace input mutation widened constructed exclusions")
	}
	if !exclusions.Matches("other", map[string]string{"app": "legacy"}) {
		t.Error("selector input mutation changed constructed exclusions")
	}
	if exclusions.Matches("other", map[string]string{"app": "api"}) {
		t.Error("selector input mutation widened constructed exclusions")
	}
}
