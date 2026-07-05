package renderedartifactfreshness

import (
	"encoding/json"
	"strings"
	"testing"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestBuildAdmitsFreshRenderedArtifactAndRejectsDigestDrift(t *testing.T) {
	input := validRenderedArtifactFreshnessInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input = validRenderedArtifactFreshnessInput()
	input["artifacts"].([]any)[0].(map[string]any)["currentArtifactDigest"] = digestB
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(mutated) error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(mutated) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func TestBuildRejectsSecretLikeReportVisibleText(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := validRenderedArtifactFreshnessInput()
	input["nonClaims"] = []any{secret}

	_, _, err := Build(input)
	if err == nil {
		t.Fatal("Build() accepted secret-shaped nonClaim")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret-shaped caller text: %v", err)
	}
	if !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("error=%v, want secret-like rejection", err)
	}
}

func validRenderedArtifactFreshnessInput() map[string]any {
	return map[string]any{
		"schemaVersion":  json.Number("1"),
		"freshnessSetId": "proofkit.test.rendered_freshness",
		"artifacts": []any{
			map[string]any{
				"artifactFormat":                "markdown",
				"artifactId":                    "proofkit.test.view",
				"artifactKind":                  "rendered_view",
				"artifactPath":                  "docs/generated/view.md",
				"authority":                     "presentation_only",
				"currentArtifactDigest":         digestA,
				"currentGenerationScopeDigest":  digestA,
				"currentRendererDigest":         digestA,
				"currentRendererVersion":        "agentic-proofkit@0.1.95",
				"currentSourceDigest":           digestA,
				"freshnessCheckRefs":            []any{"artifacts/proofkit/freshness.json"},
				"generationScopeId":             "proofkit.test.scope",
				"nonClaims":                     []any{"Rendered freshness test input does not read rendered files."},
				"recordedArtifactDigest":        digestA,
				"recordedGenerationScopeDigest": digestA,
				"recordedRendererDigest":        digestA,
				"recordedRendererVersion":       "agentic-proofkit@0.1.95",
				"recordedSourceDigest":          digestA,
				"rendererId":                    "proofkit.test.renderer",
				"sourceRefs":                    []any{"proofkit/requirements.json"},
			},
		},
		"nonClaims": []any{"Rendered freshness test input is not merge proof."},
	}
}
