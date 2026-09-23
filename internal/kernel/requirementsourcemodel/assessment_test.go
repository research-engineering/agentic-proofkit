package requirementsourcemodel

import (
	"reflect"
	"testing"
)

func TestAssessPreservesStrictModelAndDetachedSummary(t *testing.T) {
	draft := validDraft()
	strict, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := Assess(draft)
	if err != nil {
		t.Fatal(err)
	}
	model, ok := assessment.Model()
	if !ok || !reflect.DeepEqual(model, strict) || len(assessment.Violations()) != 0 {
		t.Fatal("successful assessment differs from strict normalization")
	}
	want := AssessmentSummary{
		SourceID: "proofkit.model.source", SpecPackagePath: "docs/specs/proofkit-model",
		NonClaims:        []string{"Source admission does not execute native witnesses.", "The model does not prove implementation correctness."},
		RequirementCount: 4, ActiveRequirementCount: 3, BlockingRequirementCount: 2, DeferredRequirementCount: 1,
	}
	summary, ok := assessment.Summary()
	if !ok || !reflect.DeepEqual(summary, want) {
		t.Fatalf("summary = %#v, admitted = %v, want %#v", summary, ok, want)
	}
	summary.NonClaims[0] = "Changed returned summary."
	draft.SourceNonClaims[0] = "Changed caller input."
	draft.NonClaimDefinitions[0].Statement = "Changed definition."
	again, _ := assessment.Summary()
	if !reflect.DeepEqual(again, want) {
		t.Fatal("summary aliases caller input or an earlier projection")
	}
	projection := model.Atomic()
	projection.Requirements[0].Invariant = "Changed projection."
	againModel, _ := assessment.Model()
	if !reflect.DeepEqual(againModel, strict) {
		t.Fatal("assessment model exposes mutable state")
	}
}

func TestAssessRetainsEveryPolicyOccurrence(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Draft)
		want []PolicyViolation
	}{
		{"missing deferral", func(d *Draft) { d.Groups[1].Members[0].Fields.Deferral = Own[*Deferral](nil) },
			[]PolicyViolation{policyOccurrence("missing_deferral", "REQ-MODEL-003", ".deferral", "")}},
		{"unexpected deferral", func(d *Draft) { d.Groups[0].Members[0].Fields.Deferral = d.Groups[1].Members[0].Fields.Deferral },
			[]PolicyViolation{policyOccurrence("unexpected_deferral", "REQ-MODEL-001", ".deferral", "")}},
		{"missing lifecycle evidence", func(d *Draft) { d.Groups[2].Members[0].Fields.Lifecycle.Value.EvidenceRefs = nil },
			[]PolicyViolation{policyOccurrence("missing_lifecycle_evidence", "REQ-MODEL-004", ".lifecycle.evidenceRefs", "")}},
		{"missing replacement", func(d *Draft) { d.Groups[2].Members[0].Fields.Lifecycle.Value.ReplacementRequirementIDs = nil },
			[]PolicyViolation{policyOccurrence("missing_replacement", "REQ-MODEL-004", ".lifecycle.replacementRequirementIds", "")}},
		{"unexpected replacement", func(d *Draft) {
			d.Groups[0].Members[0].Fields.Lifecycle.Value.ReplacementRequirementIDs = []string{"REQ-MODEL-002"}
		},
			[]PolicyViolation{policyOccurrence("unexpected_replacement", "REQ-MODEL-001", ".lifecycle.replacementRequirementIds", "")}},
		{"nonactive blocking", func(d *Draft) {
			d.Groups[0].Members[1].Fields.Lifecycle = Own(Lifecycle{State: LifecycleDeprecated, EvidenceRefs: []string{"docs/evidence/retirement.md"}})
		},
			[]PolicyViolation{policyOccurrence("nonactive_blocking_requirement", "REQ-MODEL-002", ".claimLevel", "")}},
		{"missing proof binding", func(d *Draft) { d.Groups[0].Members[0].Fields.ProofBindingRefs = Own([]string{}) },
			[]PolicyViolation{policyOccurrence("missing_proof_binding", "REQ-MODEL-001", ".proofBindingRefs", "")}},
		{"impact review", func(d *Draft) { d.Groups[0].Members[0].Fields.UpdatePolicy.Value.RequiresImpactDeclaration = false },
			[]PolicyViolation{policyOccurrence("impact_review_required", "REQ-MODEL-001", ".updatePolicy.requiresImpactDeclaration", "")}},
		{"proof review", func(d *Draft) { d.Groups[0].Members[0].Fields.UpdatePolicy.Value.RequiresProofBindingReview = false },
			[]PolicyViolation{policyOccurrence("proof_binding_review_required", "REQ-MODEL-001", ".updatePolicy.requiresProofBindingReview", "")}},
		{"self replacement also inactive", func(d *Draft) {
			d.Groups[2].Members[0].Fields.Lifecycle.Value.ReplacementRequirementIDs = []string{"REQ-MODEL-004"}
		},
			[]PolicyViolation{policyOccurrence("self_replacement", "REQ-MODEL-004", ".lifecycle.replacementRequirementIds", "REQ-MODEL-004"), policyOccurrence("inactive_replacement", "REQ-MODEL-004", ".lifecycle.replacementRequirementIds", "REQ-MODEL-004")}},
		{"two dangling replacements", func(d *Draft) {
			d.Groups[2].Members[0].Fields.Lifecycle.Value.ReplacementRequirementIDs = []string{"REQ-MISSING-B", "REQ-MISSING-A"}
		},
			[]PolicyViolation{policyOccurrence("dangling_replacement", "REQ-MODEL-004", ".lifecycle.replacementRequirementIds", "REQ-MISSING-A"), policyOccurrence("dangling_replacement", "REQ-MODEL-004", ".lifecycle.replacementRequirementIds", "REQ-MISSING-B")}},
		{"inactive replacement", func(d *Draft) {
			d.Groups[1].Members[0].Fields.Lifecycle = Own(Lifecycle{State: LifecycleDeprecated, EvidenceRefs: []string{"docs/evidence/retirement.md"}})
			d.Groups[2].Members[0].Fields.Lifecycle.Value.ReplacementRequirementIDs = []string{"REQ-MODEL-003"}
		}, []PolicyViolation{policyOccurrence("inactive_replacement", "REQ-MODEL-004", ".lifecycle.replacementRequirementIds", "REQ-MODEL-003")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := memberOwnedDraft()
			if _, err := Normalize(draft); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			test.edit(&draft)
			assessment, err := Assess(draft)
			if err != nil {
				t.Fatalf("policy failure became admission error: %v", err)
			}
			got := assessment.Violations()
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("violations = %#v, want %#v", got, test.want)
			}
			if model, ok := assessment.Model(); ok || !reflect.DeepEqual(model, Model{}) || !reflect.DeepEqual(assessment.model, Model{}) {
				t.Fatal("policy-failed assessment retained or exposed an invalid model")
			}
			if _, ok := assessment.Summary(); !ok {
				t.Fatal("policy-failed assessment lost admitted report operands")
			}
			_, err = Normalize(draft)
			wantError := &ValidationError{Code: test.want[0].Code, Path: test.want[0].Path}
			if !reflect.DeepEqual(err, wantError) {
				t.Fatalf("strict error = %v, want %v", err, wantError)
			}
			got[0].Code = "caller.changed"
			if !reflect.DeepEqual(assessment.Violations(), test.want) {
				t.Fatal("violation projection aliases assessment state")
			}
		})
	}
}

func TestAssessCollectsSimultaneousViolationsInCanonicalOrder(t *testing.T) {
	draft := memberOwnedDraft()
	draft.Groups[0].Members[0].Fields.ProofBindingRefs.Value = nil
	draft.Groups[0].Members[1].Fields.UpdatePolicy.Value.RequiresImpactDeclaration = false
	draft.Groups[0].Members[1].Fields.UpdatePolicy.Value.RequiresProofBindingReview = false
	draft.Groups[1].Members[0].Fields.Deferral.Value = nil
	draft.Groups[2].Members[0].Fields.Lifecycle.Value.EvidenceRefs = nil
	want := []PolicyViolation{
		policyOccurrence("missing_proof_binding", "REQ-MODEL-001", ".proofBindingRefs", ""),
		policyOccurrence("impact_review_required", "REQ-MODEL-002", ".updatePolicy.requiresImpactDeclaration", ""),
		policyOccurrence("proof_binding_review_required", "REQ-MODEL-002", ".updatePolicy.requiresProofBindingReview", ""),
		policyOccurrence("missing_deferral", "REQ-MODEL-003", ".deferral", ""),
		policyOccurrence("missing_lifecycle_evidence", "REQ-MODEL-004", ".lifecycle.evidenceRefs", ""),
	}
	for pass := 0; pass < 2; pass++ {
		assessment, err := Assess(draft)
		if err != nil || !reflect.DeepEqual(assessment.Violations(), want) {
			t.Fatalf("pass %d: violations = %#v, error = %v", pass, assessment.Violations(), err)
		}
		reverseGroups(draft.Groups)
	}
}

func TestAssessRequiresCompleteStructuralAdmission(t *testing.T) {
	for _, test := range []struct {
		name string
		code string
		edit func(*Draft)
	}{
		{"later scenario", "dangling_requirement_ref", func(d *Draft) { d.Scenarios[0].RequirementIDs = []string{"REQ-MISSING"} }},
		{"later nonclaim", "dangling_nonclaim_ref", func(d *Draft) { d.SourceNonClaimRefs = []string{"NCL-MISSING"} }},
		{"member shape", "metadata_partition_violation", func(d *Draft) { d.Groups[0].Members[0].Fields.OwnerID = Field[string]{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			draft := memberOwnedDraft()
			draft.Groups[0].Members[0].Fields.ProofBindingRefs.Value = nil
			test.edit(&draft)
			assessment, err := Assess(draft)
			if ErrorCode(err) != test.code || !reflect.DeepEqual(assessment, Assessment{}) {
				t.Fatalf("partial assessment = %#v, error = %v, want %s", assessment, err, test.code)
			}
		})
	}
	zero := Assessment{}
	if _, ok := zero.Model(); ok {
		t.Fatal("zero assessment admitted a model")
	}
	if _, ok := zero.Summary(); ok {
		t.Fatal("zero assessment admitted a summary")
	}
	draft := memberOwnedDraft()
	draft.Groups[0].Members[0].StatementCompletion = "TODO"
	limits := DefaultLimits()
	limits.MaxMembers = 1
	assessment, err := AssessWithLimits(draft, limits)
	if ErrorCode(err) != "member_budget_exceeded" || !reflect.DeepEqual(assessment, Assessment{}) {
		t.Fatalf("assessment budget priority = %v", err)
	}
}

func policyOccurrence(code, id, field, related string) PolicyViolation {
	return PolicyViolation{Code: code, Path: `requirements["` + id + `"]` + field, RequirementID: id, RelatedRequirementID: related}
}

func memberOwnedDraft() Draft {
	draft := validDraft()
	profile := draft.Profiles[0]
	for index := range draft.Groups[0].Members {
		fields := &draft.Groups[0].Members[index].Fields
		for _, id := range metadataFieldIDs {
			if metadataPresence(profile.Fields)[id] {
				setMetadataField(fields, id, cloneMetadataFields(profile.Fields))
			}
		}
	}
	draft.Groups[0].ProfileID = ""
	draft.Profiles = nil
	return draft
}
