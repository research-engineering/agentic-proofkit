package specoverviewclaims

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func TestBuildAcceptsDurableClaimWithKnownRequirementCitation(t *testing.T) {
	record, exitCode, err := Build(validBoundary())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s", exitCode, record.State)
	}
}

func TestBuildRejectsUncitedDurableClaim(t *testing.T) {
	input := validBoundary()
	claim := input["claims"].([]any)[0].(map[string]any)
	claim["citedRequirementIds"] = []any{}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnostic(t, record.RuleResults, "proofkit.spec-overview-claims.citations", "must cite")
}

func TestBuildRejectsUnknownRequirementCitation(t *testing.T) {
	input := validBoundary()
	claim := input["claims"].([]any)[0].(map[string]any)
	claim["citedRequirementIds"] = []any{"REQ-PROOFKIT-SPEC-404"}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnostic(t, record.RuleResults, "proofkit.spec-overview-claims.citations", "unknown requirement")
}

func validBoundary() map[string]any {
	return map[string]any{
		"schemaVersion":    json.Number("1"),
		"boundaryId":       "proofkit.test.overview_claims",
		"sourceId":         "proofkit.test.requirements",
		"specPackagePath":  "docs/specs/proofkit-test",
		"overviewPath":     "docs/specs/proofkit-test/overview.md",
		"requirementsPath": "docs/specs/proofkit-test/requirements.v1.json",
		"requirementIds":   []any{"REQ-PROOFKIT-SPEC-001"},
		"extractionRefs":   []any{"scripts/verify-spec-overview-claims.ts"},
		"nonClaims":        []any{"Spec overview claim test input does not prove extractor completeness."},
		"claims": []any{
			map[string]any{
				"claimId":              "proofkit.test.overview_claims.line_001",
				"claimKind":            "durable_claim",
				"citedRequirementIds":  []any{"REQ-PROOFKIT-SPEC-001"},
				"detectedMarkers":      []any{"must"},
				"dispositionRationale": "Line uses durable modal language and cites a requirement.",
				"lineDigest":           "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"lineNumber":           json.Number("1"),
				"nonClaims":            []any{"Synthetic overview claim fixture."},
			},
		},
	}
}

func assertRuleDiagnostic(t *testing.T, rules []report.RuleResult, ruleID string, want string) {
	t.Helper()
	for _, rule := range rules {
		if rule.RuleID != ruleID {
			continue
		}
		for _, diagnostic := range rule.Diagnostics {
			if text, ok := diagnostic.Value.(string); ok && strings.Contains(text, want) {
				return
			}
		}
		t.Fatalf("%s diagnostics do not contain %q: %#v", ruleID, want, rule.Diagnostics)
	}
	t.Fatalf("missing rule %s", ruleID)
}
