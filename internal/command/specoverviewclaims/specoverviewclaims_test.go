package specoverviewclaims

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
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

func TestBuildRejectsNonDurableClaimWithRequirementCitation(t *testing.T) {
	input := validBoundary()
	claim := input["claims"].([]any)[0].(map[string]any)
	claim["claimKind"] = "example_or_rationale"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertRuleDiagnostic(t, record.RuleResults, "proofkit.spec-overview-claims.citations", "non-durable")
}

func TestBuildRejectsPathDrift(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		message string
	}{
		{
			name: "overview path",
			mutate: func(input map[string]any) {
				input["overviewPath"] = "docs/specs/other/overview.md"
			},
			message: "overviewPath must equal specPackagePath/overview.md",
		},
		{
			name: "requirements path",
			mutate: func(input map[string]any) {
				input["requirementsPath"] = "docs/specs/other/requirements.v1.json"
			},
			message: "requirementsPath must equal specPackagePath/requirements.v1.json",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validBoundary()
			item.mutate(input)

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() unexpected error = %v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			assertRuleDiagnostic(t, record.RuleResults, "proofkit.spec-overview-claims.boundary", item.message)
		})
	}
}

func TestBuildRejectsInvalidOverviewClaimBoundaryFacts(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.025280307180968926567211146624399965026613890974304865664816068083127351219786")
	cases := []struct {
		name string
		err  string
		edit func(map[string]any)
	}{
		{
			name: "empty extraction refs",
			err:  "extractionRefs must be non-empty",
			edit: func(input map[string]any) {
				input["extractionRefs"] = []any{}
			},
		},
		{
			name: "invalid extraction ref path",
			err:  "must not escape the repository root",
			edit: func(input map[string]any) {
				input["extractionRefs"] = []any{"../extractor.ts"}
			},
		},
		{
			name: "empty top-level non claims",
			err:  "nonClaims must be non-empty",
			edit: func(input map[string]any) {
				input["nonClaims"] = []any{}
			},
		},
		{
			name: "invalid line digest",
			err:  "lineDigest must be sha256:<64 lowercase hex>",
			edit: func(input map[string]any) {
				firstClaim(input)["lineDigest"] = "sha256:ABC"
			},
		},
		{
			name: "empty detected markers",
			err:  "detectedMarkers must be non-empty",
			edit: func(input map[string]any) {
				firstClaim(input)["detectedMarkers"] = []any{}
			},
		},
		{
			name: "empty rationale",
			err:  "dispositionRationale must be non-empty text",
			edit: func(input map[string]any) {
				firstClaim(input)["dispositionRationale"] = " "
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validBoundary()
			item.edit(input)

			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.err) {
				t.Fatalf("Build() error=%v, want %q", err, item.err)
			}
		})
	}
}

func TestBuildRejectsNonDurableRequirementCitationsForEveryNonDurableKind(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.088402325428378402231209410729523974270570645927538147014098755159352586154144")
	for _, claimKind := range []string{"example_or_rationale", "quoted_or_code", "section_heading"} {
		t.Run(claimKind, func(t *testing.T) {
			input := validBoundary()
			firstClaim(input)["claimKind"] = claimKind

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() unexpected error = %v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			assertRuleDiagnostic(t, record.RuleResults, "proofkit.spec-overview-claims.citations", "non-durable")
		})
	}
}

func TestBuildRejectsMissingClaimNonClaims(t *testing.T) {
	input := validBoundary()
	firstClaim(input)["nonClaims"] = []any{}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "nonClaims must be non-empty") {
		t.Fatalf("Build() error=%v, want missing nonClaims admission failure", err)
	}
}

func firstClaim(input map[string]any) map[string]any {
	return input["claims"].([]any)[0].(map[string]any)
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
