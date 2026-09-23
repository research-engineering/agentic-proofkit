package requirementauthoringplan

import (
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestGroupedAuthoringRequiresEverySharedOwnerImpact(t *testing.T) {
	for _, edit := range []string{"profile", "stem", "premises"} {
		t.Run(edit, func(t *testing.T) {
			input := sharedOwnerInput()
			candidate := input["candidateRequirementSource"].(map[string]any)
			group := candidate["groups"].([]any)[0].(map[string]any)
			switch edit {
			case "profile":
				candidate["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)["riskClass"] = "critical"
			case "stem":
				group["statementStem"] = "The service"
			case "premises":
				group["sharedPremises"] = []any{"The consuming owner accepted these conditions."}
			}
			output, exit, err := Build(input)
			if err != nil || exit != 0 {
				t.Fatalf("complete shared-owner update failed: %v %#v", err, output)
			}
			preview := output["nonAuthoritativeAdmissionPreview"].(map[string]any)["requirementSourcePreview"].(map[string]any)
			if preview["groups"].([]any)[0].(map[string]any)["profileId"] != "RPROF-AUTHORING" || len(preview["profiles"].([]any)) != 1 {
				t.Fatal("authoring detached or flattened shared ownership")
			}
			if output["wholeCandidateOwnerReviewRequired"] != true {
				t.Fatal("whole-source review lost")
			}
			input["candidateUpdates"] = input["candidateUpdates"].([]any)[:1]
			failed, exit, err := Build(input)
			if err != nil || exit != 1 || failed["nonAuthoritativeAdmissionPreview"] != nil {
				t.Fatalf("missing shared impact admitted: %v %#v", err, failed)
			}
			assertOutputContains(t, failed, "changed requirement must have an explicit update row: REQ-PROOFKIT-AUTHORING-001")
			assertAuthoringRuleStatus(t, failed, "composition", "failed")
		})
	}
}

func TestGroupedAuthoringDoesNotClaimUnperformedComparison(t *testing.T) {
	input := validInput()
	candidateMember(input)["fields"].(map[string]any)["proofBindingRefs"] = []any{}
	output, exit, err := Build(input)
	if err != nil || exit != 1 || output["sourceComparisonState"] != "skipped_source_admission" || output["changedSourcePlanes"] != nil || output["nonAuthoritativeAdmissionPreview"] != nil {
		t.Fatalf("unavailable source comparison became evidence: %v %#v", err, output)
	}
	assertAuthoringRuleStatus(t, output, "candidate-source-admission", "failed")
	assertAuthoringRuleStatus(t, output, "transition-admission", "skipped")
	assertAuthoringRuleStatus(t, output, "composition", "skipped")
}

func assertAuthoringRuleStatus(t *testing.T, output map[string]any, suffix, state string) {
	t.Helper()
	for _, raw := range output["ruleResults"].([]any) {
		rule := raw.(map[string]any)
		if rule["ruleId"] == "proofkit.requirement-authoring-plan."+suffix {
			if rule["status"] != state {
				t.Fatalf("%s status=%v want=%s", suffix, rule["status"], state)
			}
			return
		}
	}
	t.Fatalf("missing rule %s", suffix)
}

func TestGroupedAuthoringSeparatesLayoutAndNoopFromAtomicChange(t *testing.T) {
	input := sharedOwnerInput()
	input["candidateUpdates"] = []any{}
	output, exit, err := Build(input)
	if err != nil || exit != 1 {
		t.Fatalf("no-op accepted: %v %#v", err, output)
	}
	candidate := input["candidateRequirementSource"].(map[string]any)
	candidate["groups"].([]any)[0].(map[string]any)["groupId"] = "RGRP-RENAMED"
	output, exit, err = Build(input)
	if err != nil || exit != 0 {
		t.Fatalf("layout-only review rejected: %v %#v", err, output)
	}
	assertStableJSONEqual(t, "layout/reference planes", []any{"layout", "references"}, output["changedSourcePlanes"])
	if len(output["candidateChangeSet"].([]any)) != 0 {
		t.Fatal("layout change invented atomic change")
	}
	input["candidateUpdates"] = sharedOwnerInput()["candidateUpdates"]
	output, exit, err = Build(input)
	if err != nil || exit != 1 {
		t.Fatalf("extraneous atomic rows accepted: %v %#v", err, output)
	}
	assertOutputContains(t, output, "candidate update must identify a changed requirement")
}

func TestGroupedAuthoringPreservesUnchangedSibling(t *testing.T) {
	input := sharedOwnerInput()
	input["candidateUpdates"] = input["candidateUpdates"].([]any)[:1]
	candidate := input["candidateRequirementSource"].(map[string]any)
	members := candidate["groups"].([]any)[0].(map[string]any)["members"].([]any)
	unchanged := cloneObject(members[1].(map[string]any))
	members[0].(map[string]any)["statementCompletion"] = "The first member now requires explicit owner review."
	output, exit, err := Build(input)
	if err != nil || exit != 0 {
		t.Fatalf("member edit rejected: %v %#v", err, output)
	}
	preview := output["nonAuthoritativeAdmissionPreview"].(map[string]any)["requirementSourcePreview"].(map[string]any)
	after := preview["groups"].([]any)[0].(map[string]any)["members"].([]any)[1].(map[string]any)
	// The formatter may omit zero-valued lifecycle/update fields. Compare through
	// the admitted source owner rather than treating whitespace/defaults as meaning.
	beforeInput, err := admitInput(sharedOwnerInput())
	if err != nil {
		t.Fatal(err)
	}
	afterInput, err := admitInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeInput.CurrentRequirementState.Requirements()[1], afterInput.CandidateRequirementResult.Source.Requirements()[1]) || after["statementCompletion"] != unchanged["statementCompletion"] {
		t.Fatal("member edit changed an untouched sibling")
	}
}

func TestGroupedAuthoringSourcePlaneInventoryIsComplete(t *testing.T) {
	for _, item := range []struct {
		value  any
		fields []string
	}{
		{requirementsourcemodel.AtomicProjection{}, []string{"SourceID", "SpecPackagePath", "SourceNonClaims", "SourceNonClaimRefs", "NonClaimDefinitions", "Vocabulary", "Requirements", "Scenarios"}},
		{requirementsourcemodel.ReferenceProjection{}, []string{"SourceID", "Derivations", "Edges"}},
	} {
		typeOf := reflect.TypeOf(item.value)
		got := []string{}
		for index := 0; index < typeOf.NumField(); index++ {
			got = append(got, typeOf.Field(index).Name)
		}
		sort.Strings(got)
		sort.Strings(item.fields)
		if !slices.Equal(got, item.fields) {
			t.Fatalf("new source plane must be classified: %v", got)
		}
	}
	for _, plane := range []string{"source_nonclaims", "nonclaim_definitions", "vocabulary", "scenarios", "derivations"} {
		t.Run(plane, func(t *testing.T) {
			input := sharedOwnerInput()
			input["candidateUpdates"] = []any{}
			base := input["currentRequirementSource"].(map[string]any)
			base["sourceNonClaimRefs"] = []any{"NCL-AUTHORING"}
			base["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-AUTHORING", "statement": "No external evidence is implied."}}
			base["vocabulary"] = []any{map[string]any{"termId": "TERM-AUTHORING", "kind": "subject", "label": "service", "definition": "The specified service."}}
			base["scenarios"] = []any{map[string]any{
				"scenarioId": "scenario.authoring", "requirementIds": []any{"REQ-PROOFKIT-AUTHORING-000"}, "parameters": []any{},
				"preconditions": []any{"The source is admitted."}, "actionSequence": []any{"Compare the candidate."}, "expectedObservations": []any{"The declared change is reported."},
				"forbiddenObservations": []any{}, "examples": []any{}, "vocabularyRefs": []any{"TERM-AUTHORING"}, "nonClaimRefs": []any{},
			}}
			base["derivations"] = []any{map[string]any{
				"derivationId": "DRV-AUTHORING", "sourceKind": "owner_decision", "requirementIds": []any{"REQ-PROOFKIT-AUTHORING-000"}, "nonClaimRefs": []any{},
				"sourceRef": map[string]any{"objectFormat": "sha1", "commitOid": "0123456789abcdef0123456789abcdef01234567", "path": "docs/decision.md", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
				"selector":  map[string]any{"start": "0", "end": "12"},
			}}
			candidate := cloneObject(base)
			input["candidateRequirementSource"] = candidate
			switch plane {
			case "source_nonclaims":
				candidate["sourceNonClaims"] = []any{"This changed boundary still grants no execution authority."}
			case "nonclaim_definitions":
				candidate["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = "This definition does not authorize publishing."
			case "vocabulary":
				candidate["vocabulary"].([]any)[0].(map[string]any)["definition"] = "The independently defined service."
			case "scenarios":
				candidate["scenarios"].([]any)[0].(map[string]any)["actionSequence"] = []any{"Inspect the candidate.", "Compare the candidate."}
			case "derivations":
				candidate["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)["end"] = "13"
			}
			output, exit, err := Build(input)
			if err != nil || exit != 0 {
				t.Fatalf("source boundary update failed: %v %#v", err, output)
			}
			assertStableJSONEqual(t, "source denial plane", []any{plane}, output["changedSourcePlanes"])
		})
	}
}

func sharedOwnerInput() map[string]any {
	input := validInput()
	source := expectedNextSource()
	group := source["groups"].([]any)[0].(map[string]any)
	group["profileId"] = "RPROF-AUTHORING"
	source["profiles"] = []any{map[string]any{"profileId": "RPROF-AUTHORING", "fields": map[string]any{"riskClass": "high"}}}
	for _, raw := range group["members"].([]any) {
		delete(raw.(map[string]any)["fields"].(map[string]any), "riskClass")
	}
	input["currentRequirementSource"], input["candidateRequirementSource"] = cloneObject(source), cloneObject(source)
	first := cloneObject(firstUpdate(input))
	first["operation"], first["requirementId"] = "modify", "REQ-PROOFKIT-AUTHORING-000"
	second := cloneObject(first)
	second["candidateId"], second["requirementId"] = "proofkit.test.authoring-candidate-b", "REQ-PROOFKIT-AUTHORING-001"
	input["candidateUpdates"] = []any{first, second}
	return input
}
