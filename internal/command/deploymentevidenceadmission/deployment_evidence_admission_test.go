package deploymentevidenceadmission

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildAdmitsCandidateEvidenceAndRejectsUnpinnedImages(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.079783886865424080333074209821707019130265643884720844463730606151075706943505")
	record, exitCode, err := Build(validDeploymentEvidenceInput())
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input := validDeploymentEvidenceInput()
	fact := input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
	fact["imageRefs"] = []any{"registry.example.test/proofkit:latest"}
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() unpinned image error=%v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "must be pinned by digest with @sha256") {
		t.Fatalf("Build() accepted unpinned image ref: exit=%d record=%s", exitCode, string(encoded))
	}
}

func TestBuildRedactsSecretLikeUnknownEvidenceFields(t *testing.T) {
	input := validDeploymentEvidenceInput()
	input["evidence"].(map[string]any)["api_key=ghp_secretvalue"] = "ignored"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "api_key") || strings.Contains(text, "ghp_secretvalue") {
		t.Fatalf("record leaked secret-like unsupported field name: %s", text)
	}
	if !strings.Contains(text, "redacted-unsupported-field-001") {
		t.Fatalf("record missing redacted unsupported field label: %s", text)
	}
}

func TestBuildRejectsSecretLikeNestedEvidenceThroughSharedScanner(t *testing.T) {
	input := validDeploymentEvidenceInput()
	input["rawOperatorEvidence"] = []any{
		map[string]any{
			"evidenceRef": "operator.note",
			"payload": map[string]any{
				"nested": []any{
					map[string]any{"token": "Authorization: Bearer abcdefghijklmnop"},
				},
			},
		},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "abcdefghijklmnop") || strings.Contains(text, "Authorization") {
		t.Fatalf("record leaked secret-shaped nested value: %s", text)
	}
	if !strings.Contains(text, "rawOperatorEvidence[0].payload.nested[0].token must not contain secret-shaped material") {
		t.Fatalf("record missing shared scanner path finding: %s", text)
	}
}

func validDeploymentEvidenceInput() map[string]any {
	nonClaim := "Deployment evidence test fixture does not prove live deployment."
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"admissionId":   "proofkit.test.deployment",
		"evidence": map[string]any{
			"schema":          "deployment.evidence.v1",
			"proofScope":      "local",
			"deploymentClaim": "candidate",
			"evidenceId":      "proofkit.test.evidence",
			"facts": []any{
				map[string]any{
					"factId":        "proofkit.test.fact",
					"kind":          "release_artifact",
					"sourceCommits": []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
					"imageRefs":     []any{"registry.example.test/proofkit@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				},
			},
			"nonClaims": []any{nonClaim},
		},
		"policy": map[string]any{
			"expectedDeploymentClaim":       "candidate",
			"expectedEvidenceSchema":        "deployment.evidence.v1",
			"expectedProofScope":            "local",
			"forbiddenValueIndicators":      []any{},
			"localRefIndicators":            []any{"localhost", "127.0.0.1"},
			"requiredFactIds":               []any{"proofkit.test.fact"},
			"requiredFactKinds":             []any{"release_artifact"},
			"requiredNonClaims":             []any{nonClaim},
			"requireDigestPinnedImageRefs":  true,
			"requireLowercaseSourceCommits": true,
			"temporaryEndpointHostSuffixes": []any{"trycloudflare.com"},
		},
		"rawOperatorEvidence": []any{},
		"nonClaims":           []any{"Deployment evidence admission test fixture is not release proof."},
	}
}
