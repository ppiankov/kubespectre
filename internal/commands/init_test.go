package commands

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// WO-45/WO-47: minimal decode target for asserting sampleRBAC's rendered
// rules, not a general-purpose RBAC type.
type rbacPolicyRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

// WO-45/WO-47: minimal decode target for locating the ClusterRole document
// among sampleRBAC's multiple YAML documents.
type rbacClusterRoleDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Rules []rbacPolicyRule `yaml:"rules"`
}

// WO-45/WO-47: findClusterRoleRule decodes each YAML document in sampleRBAC
// and returns the first rule matching the given apiGroup/resource, if any.
func findClusterRoleRule(t *testing.T, apiGroup, resource string) *rbacPolicyRule {
	t.Helper()
	for _, doc := range strings.Split(sampleRBAC, "\n---\n") {
		var parsed rbacClusterRoleDoc
		if err := yaml.Unmarshal([]byte(doc), &parsed); err != nil {
			continue
		}
		if parsed.Kind != "ClusterRole" {
			continue
		}
		for i := range parsed.Rules {
			rule := parsed.Rules[i]
			hasGroup, hasResource := false, false
			for _, g := range rule.APIGroups {
				if g == apiGroup {
					hasGroup = true
				}
			}
			for _, r := range rule.Resources {
				if r == resource {
					hasResource = true
				}
			}
			if hasGroup && hasResource {
				return &rule
			}
		}
	}
	return nil
}

// WO-45: the sample ClusterRole must grant get/list on the cluster-scoped
// persistentvolumes resource (distinct from persistentvolumeclaims) --
// without it, WO-40's PersistentVolumeScanner fails with RBAC-denied on
// every audit run for anyone following the documented init workflow.
func TestSampleRBAC_GrantsPersistentVolumesAccess(t *testing.T) {
	rule := findClusterRoleRule(t, "", "persistentvolumes")
	if rule == nil {
		t.Fatal("no rule grants access to the cluster-scoped persistentvolumes resource")
	}
	for _, verb := range []string{"get", "list"} {
		found := false
		for _, v := range rule.Verbs {
			if v == verb {
				found = true
			}
		}
		if !found {
			t.Errorf("persistentvolumes rule verbs = %v, missing %q", rule.Verbs, verb)
		}
	}
}

// WO-45: persistentvolumeclaims (namespaced) must remain granted separately
// -- confirms the fix added a new rule rather than accidentally replacing
// the existing one.
func TestSampleRBAC_GrantsPersistentVolumeClaimsAccess(t *testing.T) {
	rule := findClusterRoleRule(t, "", "persistentvolumeclaims")
	if rule == nil {
		t.Fatal("no rule grants access to persistentvolumeclaims -- regression from the persistentvolumes fix")
	}
}

// WO-47: the sample ClusterRole must grant get/list on the cluster-scoped
// nodes resource -- without it, NodeScanner fails with RBAC-denied on every
// audit run for anyone following the documented init workflow.
func TestSampleRBAC_GrantsNodesAccess(t *testing.T) {
	rule := findClusterRoleRule(t, "", "nodes")
	if rule == nil {
		t.Fatal("no rule grants access to the cluster-scoped nodes resource")
	}
	for _, verb := range []string{"get", "list"} {
		found := false
		for _, v := range rule.Verbs {
			if v == verb {
				found = true
			}
		}
		if !found {
			t.Errorf("nodes rule verbs = %v, missing %q", rule.Verbs, verb)
		}
	}
}
