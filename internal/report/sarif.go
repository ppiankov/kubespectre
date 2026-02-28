package report

import (
	"encoding/json"
	"fmt"

	"github.com/ppiankov/kubespectre/internal/k8s"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	DefaultConfig    sarifDefaultLevel `json:"defaultConfiguration"`
}

type sarifDefaultLevel struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLoc     `json:"locations,omitempty"`
	Props     map[string]any `json:"properties,omitempty"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// Generate writes SARIF v2.1.0 output.
func (r *SARIFReporter) Generate(data Data) error {
	rules := buildSARIFRules()
	results := make([]sarifResult, 0, len(data.Findings))

	for _, f := range data.Findings {
		uri := buildSARIFURI(f)
		results = append(results, sarifResult{
			RuleID:  string(f.ID),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLoc{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: uri},
					},
				},
			},
			Props: f.Metadata,
		})
	}

	rpt := sarifReport{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    data.Tool,
						Version: data.Version,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rpt); err != nil {
		return fmt.Errorf("encode SARIF report: %w", err)
	}
	return nil
}

func buildSARIFURI(f k8s.Finding) string {
	if f.Namespace != "" {
		return fmt.Sprintf("k8s://%s/%s/%s/%s", f.Cluster, f.Namespace, f.ResourceType, f.ResourceID)
	}
	return fmt.Sprintf("k8s://%s/%s/%s", f.Cluster, f.ResourceType, f.ResourceID)
}

func sarifLevel(s k8s.Severity) string {
	switch s {
	case k8s.SeverityCritical, k8s.SeverityHigh:
		return "error"
	case k8s.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildSARIFRules() []sarifRule {
	return []sarifRule{
		{ID: string(k8s.FindingWildcardRBAC), ShortDescription: sarifMessage{Text: "Wildcard RBAC permissions"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingClusterAdminBinding), ShortDescription: sarifMessage{Text: "Cluster-admin binding to non-system SA"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingPrivilegedContainer), ShortDescription: sarifMessage{Text: "Privileged container"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingHostNetwork), ShortDescription: sarifMessage{Text: "Host network access"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingHostPID), ShortDescription: sarifMessage{Text: "Host PID namespace access"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingMissingNetworkPolicy), ShortDescription: sarifMessage{Text: "Missing network policy"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingUnencryptedSecrets), ShortDescription: sarifMessage{Text: "Unencrypted secrets in etcd"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingUnusedSecretMount), ShortDescription: sarifMessage{Text: "Unused secret mount"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingStaleSecret), ShortDescription: sarifMessage{Text: "Stale secret"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(k8s.FindingDefaultServiceAccount), ShortDescription: sarifMessage{Text: "Default service account used"}, DefaultConfig: sarifDefaultLevel{Level: "warning"}},
		{ID: string(k8s.FindingAutomountToken), ShortDescription: sarifMessage{Text: "Auto-mounted service account token"}, DefaultConfig: sarifDefaultLevel{Level: "warning"}},
		{ID: string(k8s.FindingNoImageDigest), ShortDescription: sarifMessage{Text: "Image without digest pinning"}, DefaultConfig: sarifDefaultLevel{Level: "warning"}},
		{ID: string(k8s.FindingUntrustedRegistry), ShortDescription: sarifMessage{Text: "Image from untrusted registry"}, DefaultConfig: sarifDefaultLevel{Level: "warning"}},
		{ID: string(k8s.FindingMissingAuditPolicy), ShortDescription: sarifMessage{Text: "Missing audit policy"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
	}
}
