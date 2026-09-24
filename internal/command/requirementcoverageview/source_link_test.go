package requirementcoverageview

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

func TestCoverageSourceLinkRejectsStaleAndForgedRequirements(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	output, err := build(input)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := requirementsourceadmission.Evaluate(input["requirementSource"])
	if err != nil || admitted.ExitCode != 0 {
		t.Fatalf("source admission: %v", err)
	}
	if err := AdmitSourceLink(output, admitted.Source); err != nil {
		t.Fatalf("current coverage source rejected: %v", err)
	}
	row := output["requirementCoverage"].([]any)[0].(map[string]any)
	row["invariant"] = "A stale invariant was substituted."
	if err := AdmitSourceLink(output, admitted.Source); err == nil || !strings.Contains(err.Error(), "invariant") {
		t.Fatalf("forged requirement admitted: %v", err)
	}
	row["invariant"] = admitted.Source.Requirements()[0].Invariant
	source := input["requirementSource"].(map[string]any)
	source["sourceNonClaims"] = []any{"A revised source does not establish witness execution."}
	revised, err := requirementsourceadmission.Evaluate(source)
	if err != nil || revised.ExitCode != 0 {
		t.Fatalf("revised source admission: %v", err)
	}
	if err := AdmitSourceLink(output, revised.Source); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("stale coverage source admitted: %v", err)
	}
}

func TestCoverageSourceLinkPreservesSourceLevelNonClaims(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	output, err := build(input)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := requirementsourceadmission.Evaluate(input["requirementSource"])
	if err != nil || admitted.ExitCode != 0 {
		t.Fatalf("source admission: %v", err)
	}
	if err := AdmitSourceLink(output, admitted.Source); err != nil {
		t.Fatalf("source boundary rejected: %v", err)
	}
	removed := admitted.Source.NonClaims()[0]
	retained := []any{}
	for _, raw := range output["nonClaims"].([]any) {
		if raw != removed {
			retained = append(retained, raw)
		}
	}
	output["nonClaims"] = retained
	if err := AdmitSourceLink(output, admitted.Source); err == nil || !strings.Contains(err.Error(), "source non-claim") {
		t.Fatalf("missing source boundary admitted: %v", err)
	}
}

func TestCoverageSourceLinkChecksScenarioMembershipWithoutProofBinding(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	output, err := build(input)
	if err != nil {
		t.Fatal(err)
	}
	source := input["requirementSource"].(map[string]any)
	group := source["groups"].([]any)[0].(map[string]any)
	first := group["members"].([]any)[0].(map[string]any)
	group["members"] = append(group["members"].([]any), map[string]any{
		"requirementId": "REQ-PROOFKIT-COVERAGE-002", "statementCompletion": first["statementCompletion"], "fields": first["fields"],
	})
	source["scenarios"] = []any{map[string]any{
		"scenarioId": "proofkit.coverage.scenario", "requirementIds": []any{"REQ-PROOFKIT-COVERAGE-002"},
		"parameters": []any{}, "preconditions": []any{"A request is ready."},
		"actionSequence": []any{"Submit the request."}, "expectedObservations": []any{"The response is accepted."},
		"forbiddenObservations": []any{}, "examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}}
	admitted, err := requirementsourceadmission.Evaluate(source)
	if err != nil || admitted.ExitCode != 0 {
		t.Fatalf("source admission: %v", err)
	}
	output["sourceDigest"], err = requirementsourceadmission.SourceDigest(admitted.Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := AdmitSourceLink(output, admitted.Source); err == nil || !strings.Contains(err.Error(), "scenario") {
		t.Fatalf("wrong scenario membership admitted: %v", err)
	}
	source["scenarios"].([]any)[0].(map[string]any)["requirementIds"] = []any{"REQ-PROOFKIT-COVERAGE-001", "REQ-PROOFKIT-COVERAGE-002"}
	admitted, err = requirementsourceadmission.Evaluate(source)
	if err != nil || admitted.ExitCode != 0 {
		t.Fatalf("shared scenario admission: %v", err)
	}
	output["sourceDigest"], err = requirementsourceadmission.SourceDigest(admitted.Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := AdmitSourceLink(output, admitted.Source); err != nil {
		t.Fatalf("shared scenario membership rejected: %v", err)
	}
}

func TestCoverageSourceLinkRejectsForgedNonClaimDefinition(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	source := input["requirementSource"].(map[string]any)
	source["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-COVERAGE", "statement": "Declared coverage is not execution."}}
	fields := source["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	fields["nonClaimRefs"] = []any{"NCL-COVERAGE"}
	output, err := build(input)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := requirementsourceadmission.Evaluate(source)
	if err != nil || admitted.ExitCode != 0 {
		t.Fatalf("source admission: %v", err)
	}
	if err := AdmitSourceLink(output, admitted.Source); err != nil {
		t.Fatalf("current definition rejected: %v", err)
	}
	output["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = "A forged interpretation of the source denial."
	if err := AdmitSourceLink(output, admitted.Source); err == nil || !strings.Contains(err.Error(), "non-claim definitions") {
		t.Fatalf("forged definition admitted: %v", err)
	}
}
