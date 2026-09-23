package requirementsourceadmission

import (
	"reflect"
	"testing"
)

func TestSourceProjectionsCannotMutateAdmittedSnapshot(t *testing.T) {
	input := validSource()
	firstMember := sourceMember(input, 0)
	first := firstMember["fields"].(map[string]any)
	second := sourceMember(validSource(), 0)
	second["requirementId"] = "REQ-PROOFKIT-SOURCE-002"
	input["groups"].([]any)[0].(map[string]any)["members"] = []any{firstMember, second}
	first["claimLevel"] = "deferred"
	first["externalNonClaimRefs"] = []any{"boundary.test"}
	first["nonClaimRefs"] = []any{"NCL-TEST"}
	input["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-TEST", "statement": "No runtime proof is inferred."}}
	input["groups"].([]any)[0].(map[string]any)["sharedPremises"] = []any{"The owner admitted the current source."}
	first["lifecycle"] = map[string]any{
		"state": "superseded", "evidenceRefs": []any{"proof/lifecycle.json"},
		"replacementRequirementIds": []any{"REQ-PROOFKIT-SOURCE-002"},
	}
	first["deferral"] = map[string]any{
		"ownerId": "owner.test", "riskAcceptedBy": "owner.test", "reviewCondition": "Review the replacement.",
		"expiryRef": "review.next", "mergePolicy": "policy.test", "evidenceRefs": []any{"proof/deferral.json"},
	}
	result, err := Evaluate(input)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("admit rich source: %v; failures=%v", err, result.Failures)
	}
	source := result.Source
	want := mustSourceValue(t, source)
	if source.RequirementCount() != 2 || source.SourceID() != input["sourceId"] ||
		source.SpecPackagePath() != input["specPackagePath"] || source.OverviewPath() != "docs/specs/proofkit-test/overview.md" ||
		source.RequirementsPath() != "docs/specs/proofkit-test/requirements.v2.json" {
		t.Fatal("identity or count projection differs from admitted input")
	}
	for name, mutate := range map[string]func([]Requirement){
		"member":             func(values []Requirement) { values[0].RequirementID = "REQ-CHANGED" },
		"nonclaim refs":      func(values []Requirement) { values[0].NonClaimRefs[0] = "changed" },
		"external refs":      func(values []Requirement) { values[0].ExternalNonClaimRefs[0] = "changed" },
		"shared premises":    func(values []Requirement) { values[0].SharedPremises[0] = "Changed." },
		"nonclaims":          func(values []Requirement) { values[0].NonClaims[0] = "Changed." },
		"proof refs":         func(values []Requirement) { values[0].ProofBindingRefs[0] = "changed.json" },
		"lifecycle evidence": func(values []Requirement) { values[0].Lifecycle.EvidenceRefs[0] = "changed.json" },
		"replacements":       func(values []Requirement) { values[0].Lifecycle.ReplacementRequirementIDs[0] = "REQ-CHANGED" },
		"deferral":           func(values []Requirement) { values[0].Deferral.OwnerID = "changed" },
		"deferral evidence":  func(values []Requirement) { values[0].Deferral.EvidenceRefs[0] = "changed.json" },
	} {
		t.Run(name, func(t *testing.T) {
			mutate(source.Requirements())
			if got := mustSourceValue(t, source); !reflect.DeepEqual(got, want) {
				t.Fatalf("detached projection mutated admitted source: got=%#v want=%#v", got, want)
			}
		})
	}
	source.NonClaims()[0] = "Changed."
	input["sourceNonClaims"].([]any)[0] = "Changed caller source boundary."
	first["nonClaimRefs"].([]any)[0] = "changed.caller.ref"
	first["deferral"].(map[string]any)["evidenceRefs"].([]any)[0] = "caller/changed.json"
	if got := mustSourceValue(t, source); !reflect.DeepEqual(got, want) {
		t.Fatalf("source boundary or caller mutation changed admitted source: %#v", got)
	}
}

func TestSourceHasNoPublicMutableFields(t *testing.T) {
	typeOfSource := reflect.TypeFor[Source]()
	for index := 0; index < typeOfSource.NumField(); index++ {
		if field := typeOfSource.Field(index); field.IsExported() {
			t.Fatalf("source snapshot exposes mutable field %s", field.Name)
		}
	}
}
