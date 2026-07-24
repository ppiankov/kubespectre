// Package release holds deterministic source-contract tests that pin the
// release workflow's integrity guards so they cannot silently regress.
package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// WO-27: the release workflow must serialize per-tag runs, gate on a CHANGELOG
// entry before building, and run goreleaser only after both guards pass.
func TestReleaseWorkflowIntegrityGuards(t *testing.T) {
	release := readWorkflow(t, ".github/workflows/release.yml")

	on, ok := release["on"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing on block")
	}
	push, ok := on["push"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing push trigger")
	}
	tags, ok := push["tags"].([]any)
	if !ok || len(tags) == 0 {
		t.Fatalf("release.yml missing tags trigger")
	}
	if tags[0] != "v*" {
		t.Fatalf("release.yml tags trigger = %v, want v*", tags[0])
	}

	// WO-27: tag-normalized concurrency group with no in-progress cancellation.
	concurrency, ok := release["concurrency"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing concurrency block")
	}
	group, ok := concurrency["group"].(string)
	if !ok {
		t.Fatalf("release.yml concurrency.group missing")
	}
	if group != "release-${{ github.ref }}" {
		t.Fatalf("release.yml concurrency group = %q, want release-${{ github.ref }}", group)
	}
	if cancel, ok := concurrency["cancel-in-progress"].(bool); !ok || cancel {
		t.Fatalf("release.yml concurrency cancel-in-progress = %v, want false", concurrency["cancel-in-progress"])
	}

	jobs, ok := release["jobs"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing jobs block")
	}

	// WO-27: a dedicated job must verify the CHANGELOG entry against the tag.
	validateJob, ok := jobs["validate-changelog"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing validate-changelog job")
	}
	validateSteps, ok := validateJob["steps"].([]any)
	if !ok {
		t.Fatalf("release.yml validate-changelog job missing steps")
	}
	if !stepMatches(validateSteps, func(name, run string) bool {
		return strings.Contains(strings.ToLower(name), "changelog") || strings.Contains(run, "CHANGELOG.md")
	}) {
		t.Fatalf("release.yml validate-changelog job missing a CHANGELOG.md check step")
	}

	// WO-27: the release job must depend on BOTH guards and only then run goreleaser.
	releaseJob, ok := jobs["release"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing release job")
	}
	needs := jobNeeds(t, releaseJob)
	for _, required := range []string{"test", "validate-changelog"} {
		if !needs[required] {
			t.Fatalf("release.yml release job must depend on %q; needs = %v", required, needs)
		}
	}
	releaseSteps, ok := releaseJob["steps"].([]any)
	if !ok {
		t.Fatalf("release.yml release job missing steps")
	}
	if !stepMatches(releaseSteps, func(_, run string) bool {
		return strings.Contains(run, "release --clean")
	}) && !usesGoreleaserAction(releaseSteps) {
		t.Fatalf("release.yml release job missing a goreleaser release step")
	}
}

// WO-27: the GoReleaser config must declare archives before checksum before the
// Homebrew formula so the formula can never reference an unpublished asset sha.
func TestGoreleaserAssetBeforeFormulaOrdering(t *testing.T) {
	config := sourceWorkflow(t, ".goreleaser.yml")

	archivesIndex := strings.Index(config, "\narchives:")
	checksumIndex := strings.Index(config, "\nchecksum:")
	brewsIndex := strings.Index(config, "\nbrews:")

	if archivesIndex == -1 {
		t.Fatalf(".goreleaser.yml missing archives block")
	}
	if checksumIndex == -1 {
		t.Fatalf(".goreleaser.yml missing checksum block")
	}
	if brewsIndex == -1 {
		t.Fatalf(".goreleaser.yml missing brews block")
	}
	if archivesIndex >= checksumIndex || checksumIndex >= brewsIndex {
		t.Fatalf(".goreleaser.yml order archives(%d) < checksum(%d) < brews(%d) violated",
			archivesIndex, checksumIndex, brewsIndex)
	}
}

// WO-27: the Homebrew tap target must stay pinned to the ppiankov tap so the
// formula publish never drifts to an unexpected repository.
func TestGoreleaserHomebrewTapTarget(t *testing.T) {
	config := readWorkflow(t, ".goreleaser.yml")
	brews, ok := config["brews"].([]any)
	if !ok || len(brews) == 0 {
		t.Fatalf(".goreleaser.yml missing brews entries")
	}
	first, ok := brews[0].(map[string]any)
	if !ok {
		t.Fatalf(".goreleaser.yml brews[0] shape = %T, want map", brews[0])
	}
	repository, ok := first["repository"].(map[string]any)
	if !ok {
		t.Fatalf(".goreleaser.yml brews[0].repository missing")
	}
	if repository["owner"] != "ppiankov" {
		t.Fatalf(".goreleaser.yml brews tap owner = %v, want ppiankov", repository["owner"])
	}
	if repository["name"] != "homebrew-tap" {
		t.Fatalf(".goreleaser.yml brews tap name = %v, want homebrew-tap", repository["name"])
	}
}

// WO-27: report whether any release step uses the goreleaser-action, which runs
// `release --clean` internally without a shell `run:` line.
func usesGoreleaserAction(steps []any) bool {
	for _, stepValue := range steps {
		step, ok := stepValue.(map[string]any)
		if !ok {
			continue
		}
		if uses, _ := step["uses"].(string); strings.Contains(uses, "goreleaser/goreleaser-action") {
			return true
		}
	}
	return false
}

// WO-27: stepMatches reports whether any step satisfies the predicate on its
// name and run fields.
func stepMatches(steps []any, predicate func(name, run string) bool) bool {
	for _, stepValue := range steps {
		step, ok := stepValue.(map[string]any)
		if !ok {
			continue
		}
		name, _ := step["name"].(string)
		run, _ := step["run"].(string)
		if predicate(name, run) {
			return true
		}
	}
	return false
}

// WO-27: jobNeeds normalizes a job's needs field (string or list) into a set.
func jobNeeds(t *testing.T, job map[string]any) map[string]bool {
	t.Helper()
	needs := map[string]bool{}
	switch value := job["needs"].(type) {
	case string:
		needs[value] = true
	case []any:
		for _, item := range value {
			if name, ok := item.(string); ok {
				needs[name] = true
			}
		}
	default:
		t.Fatalf("release job needs shape = %T, want string or list", job["needs"])
	}
	return needs
}

// WO-27: read and decode a workflow or config file once per contract assertion.
func readWorkflow(t *testing.T, relativePath string) map[string]any {
	t.Helper()
	workflow := map[string]any{}
	if err := yaml.Unmarshal([]byte(sourceWorkflow(t, relativePath)), &workflow); err != nil {
		t.Fatalf("unmarshal %s: %v", relativePath, err)
	}
	return workflow
}

// WO-27: load fixtures from the repository root (two levels up from this package).
func sourceWorkflow(t *testing.T, relativePath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", relativePath))
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return string(data)
}
