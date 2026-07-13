package requirementsourceadmission

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"sort"
	"strings"
	"testing"
)

func TestComparisonFieldsExhaustRequirementProjection(t *testing.T) {
	result, err := Evaluate(validSource())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	requirement := result.Source.Requirements[0]
	requirement.Deferral = &Deferral{}
	projection := RequirementValue(requirement)
	want := make([]string, 0, len(projection)-1)
	for key := range projection {
		if key != "requirementId" {
			want = append(want, key)
		}
	}
	sort.Strings(want)
	fields := ComparisonFields(requirement)
	got := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, field := range fields {
		if _, exists := seen[field.Name]; exists {
			t.Fatalf("ComparisonFields() contains duplicate %q", field.Name)
		}
		seen[field.Name] = struct{}{}
		got = append(got, field.Name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ComparisonFields()=%v, want exhaustive projection fields %v", got, want)
	}
}

func TestEvaluateAcceptsActiveBlockingRequirementWithProofRoute(t *testing.T) {
	result, err := Evaluate(validSource())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("Evaluate() exit=%d state=%s", result.ExitCode, result.Report.State)
	}
}

func TestEvaluateRejectsBlockingRequirementWithoutProofRoute(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.100459756653360126553817815808542023226844129025849093125858776155160578989149")
	input := validSource()
	requirement := input["requirements"].([]any)[0].(map[string]any)
	requirement["proofBindingRefs"] = []any{}

	result, err := Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("Evaluate() exit=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	assertFailure(t, result, "must route to proof bindings")
}

func TestEvaluateRejectsUnknownTopLevelField(t *testing.T) {
	input := validSource()
	input["legacyOracle"] = true

	_, err := Evaluate(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Evaluate() error=%v, want unsupported field", err)
	}
}

func validSource() map[string]any {
	return map[string]any{
		"schemaVersion":    json.Number("1"),
		"sourceId":         "proofkit.test.requirements",
		"specPackagePath":  "docs/specs/proofkit-test",
		"overviewPath":     "docs/specs/proofkit-test/overview.md",
		"requirementsPath": "docs/specs/proofkit-test/requirements.v1.json",
		"nonClaims":        []any{"Requirement source test input does not claim production readiness."},
		"requirements": []any{
			map[string]any{
				"claimLevel": "blocking",
				"deferral":   nil,
				"invariant":  "Proofkit test requirement must preserve source admission semantics.",
				"lifecycle": map[string]any{
					"evidenceRefs":              []any{},
					"replacementRequirementIds": []any{},
					"state":                     "active",
				},
				"nonClaimRefs": []any{},
				"nonClaims":    []any{"This test requirement does not execute native witnesses."},
				"ownerId":      "proofkit.test",
				"proofBindingRefs": []any{
					"docs/contracts/requirement-proof-binding-sources.v1.json",
				},
				"requirementId": "REQ-PROOFKIT-SOURCE-001",
				"riskClass":     "medium",
				"updatePolicy": map[string]any{
					"requiresImpactDeclaration":  true,
					"requiresProofBindingReview": true,
					"reviewOwnerId":              "proofkit.test",
				},
			},
		},
	}
}

func assertFailure(t *testing.T, result Result, want string) {
	t.Helper()
	for _, failure := range result.Failures {
		if strings.Contains(failure, want) {
			return
		}
	}
	t.Fatalf("failures do not contain %q: %#v", want, result.Failures)
}
