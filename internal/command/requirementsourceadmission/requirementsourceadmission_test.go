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
	requirement := result.Source.Requirements()[0]
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
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.072077823236321697138427281525724834744695054203573403855376161988559434150965")
	input := validSource()
	requirement := sourceMember(input, 0)["fields"].(map[string]any)
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
	if err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("Evaluate() error=%v, want unknown field", err)
	}
}

func validSource() map[string]any {
	return map[string]any{
		"schemaVersion":   json.Number("2"),
		"kind":            "proofkit.requirement-source",
		"sourceId":        "proofkit.test.requirements",
		"specPackagePath": "docs/specs/proofkit-test",
		"sourceNonClaims": []any{"Requirement source test input does not claim production readiness."},
		"groups": []any{map[string]any{
			"groupId": "RGRP-TEST", "profileId": "", "statementStem": "", "sharedPremises": []any{},
			"members": []any{
				map[string]any{
					"requirementId":       "REQ-PROOFKIT-SOURCE-001",
					"statementCompletion": "Proofkit test requirement must preserve source admission semantics.",
					"fields": map[string]any{
						"claimLevel": "blocking",
						"deferral":   nil,
						"lifecycle": map[string]any{
							"evidenceRefs":              []any{},
							"replacementRequirementIds": []any{},
							"state":                     "active",
						},
						"nonClaimRefs":         []any{},
						"externalNonClaimRefs": []any{},
						"nonClaims":            []any{"This test requirement does not execute native witnesses."},
						"ownerId":              "proofkit.test",
						"proofBindingRefs": []any{
							"docs/contracts/requirement-proof-binding-sources.v1.json",
						},
						"riskClass": "medium",
						"updatePolicy": map[string]any{
							"requiresImpactDeclaration":  true,
							"requiresProofBindingReview": true,
							"reviewOwnerId":              "proofkit.test",
						},
					},
				},
			},
		}},
	}
}

func sourceMember(source map[string]any, index int) map[string]any {
	return source["groups"].([]any)[0].(map[string]any)["members"].([]any)[index].(map[string]any)
}

func mustSourceValue(t *testing.T, source Source) map[string]any {
	t.Helper()
	value, err := SourceValue(source)
	if err != nil {
		t.Fatal(err)
	}
	return value
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
