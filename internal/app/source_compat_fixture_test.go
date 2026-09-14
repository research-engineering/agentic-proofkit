package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	legacy "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	codec "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func sourceCompatJSON(t testing.TB, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sourceCompatDecode(t testing.TB, data []byte) any {
	t.Helper()
	value, err := admission.DecodeJSON(bytes.NewReader(data), maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func sourceCompatAdmit(t testing.TB, raw any) legacy.Source {
	t.Helper()
	value := sourceCompatDecode(t, sourceCompatJSON(t, raw))
	result, err := legacy.Evaluate(value)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("legacy source premise: err=%v failures=%v", err, result.Failures)
	}
	return result.Source
}

func sourceCompatSource(count int) legacy.Source {
	source := legacy.Source{SourceID: "source.compatibility", SpecPackagePath: "docs/specs/compatibility",
		OverviewPath: "docs/specs/compatibility/overview.md", RequirementsPath: "docs/specs/compatibility/requirements.v1.json",
		NonClaims: []string{"Source compatibility does not prove execution."}, Requirements: []legacy.Requirement{}}
	for i := range count {
		source.Requirements = append(source.Requirements, legacy.Requirement{
			RequirementID: fmt.Sprintf("REQ-COMPAT-%05d", i), OwnerID: "owner.requirement",
			Invariant: "The operation preserves its independently declared input.", ClaimLevel: "advisory", RiskClass: "low",
			Lifecycle: legacy.Lifecycle{State: "active"}, NonClaims: []string{"No native witness is asserted."},
			UpdatePolicy: legacy.UpdatePolicy{ReviewOwnerID: "owner.review"},
		})
	}
	return source
}

// This test-only mapping has no public converter or scenario-body authority.
func sourceCompatDraft(source legacy.Source) model.Draft {
	draft := model.Draft{SourceID: source.SourceID, SpecPackagePath: source.SpecPackagePath, SourceNonClaims: source.NonClaims}
	for i, r := range source.Requirements {
		if i%model.DefaultLimits().MaxMembersPerGroup == 0 {
			draft.Groups = append(draft.Groups, model.Group{GroupID: fmt.Sprintf("RGRP-COMPAT-%05d", len(draft.Groups))})
		}
		var deferral *model.Deferral
		if r.Deferral != nil {
			d := r.Deferral
			deferral = &model.Deferral{OwnerID: d.OwnerID, RiskAcceptedBy: d.RiskAcceptedBy, ReviewCondition: d.ReviewCondition,
				ExpiryRef: d.ExpiryRef, MergePolicy: d.MergePolicy, EvidenceRefs: d.EvidenceRefs}
		}
		member := model.Member{RequirementID: r.RequirementID, StatementCompletion: r.Invariant, Fields: model.MetadataFields{
			OwnerID: model.Own(r.OwnerID), ClaimLevel: model.Own(model.ClaimLevel(r.ClaimLevel)), RiskClass: model.Own(model.RiskClass(r.RiskClass)),
			NonClaims: model.Own(r.NonClaims), ExternalNonClaimRefs: model.Own(r.NonClaimRefs), NonClaimRefs: model.Own([]string{}), ProofBindingRefs: model.Own(r.ProofBindingRefs),
			Lifecycle: model.Own(model.Lifecycle{State: model.LifecycleState(r.Lifecycle.State), EvidenceRefs: r.Lifecycle.EvidenceRefs, ReplacementRequirementIDs: r.Lifecycle.ReplacementRequirementIDs}),
			Deferral:  model.Own(deferral), UpdatePolicy: model.Own(model.UpdatePolicy{ReviewOwnerID: r.UpdatePolicy.ReviewOwnerID,
				RequiresImpactDeclaration: r.UpdatePolicy.RequiresImpactDeclaration, RequiresProofBindingReview: r.UpdatePolicy.RequiresProofBindingReview}),
		}}
		last := len(draft.Groups) - 1
		draft.Groups[last].Members = append(draft.Groups[last].Members, member)
	}
	return draft
}

func sourceCompatLegacy(candidate model.Model) (legacy.Source, error) {
	a := candidate.Atomic()
	if len(a.SourceNonClaimRefs)+len(a.NonClaimDefinitions)+len(a.Vocabulary)+len(a.Scenarios)+len(candidate.References().Derivations) != 0 {
		return legacy.Source{}, fmt.Errorf("candidate has non-legacy semantics")
	}
	result := legacy.Source{SourceID: a.SourceID, SpecPackagePath: a.SpecPackagePath,
		OverviewPath: a.SpecPackagePath + "/overview.md", RequirementsPath: a.SpecPackagePath + "/requirements.v1.json",
		NonClaims: a.SourceNonClaims, Requirements: []legacy.Requirement{}}
	for _, r := range a.Requirements {
		if len(r.SharedPremises)+len(r.NonClaimRefs) != 0 {
			return legacy.Source{}, fmt.Errorf("candidate has non-legacy requirement semantics")
		}
		var deferral *legacy.Deferral
		if r.Deferral != nil {
			d := r.Deferral
			deferral = &legacy.Deferral{OwnerID: d.OwnerID, RiskAcceptedBy: d.RiskAcceptedBy, ReviewCondition: d.ReviewCondition,
				ExpiryRef: d.ExpiryRef, MergePolicy: d.MergePolicy, EvidenceRefs: d.EvidenceRefs}
		}
		result.Requirements = append(result.Requirements, legacy.Requirement{
			RequirementID: r.RequirementID, Invariant: r.Invariant, OwnerID: r.OwnerID, ClaimLevel: string(r.ClaimLevel), RiskClass: string(r.RiskClass),
			NonClaimRefs: r.ExternalNonClaimRefs, NonClaims: r.NonClaims, ProofBindingRefs: r.ProofBindingRefs,
			Lifecycle: legacy.Lifecycle{State: string(r.Lifecycle.State), EvidenceRefs: r.Lifecycle.EvidenceRefs, ReplacementRequirementIDs: r.Lifecycle.ReplacementRequirementIDs},
			Deferral:  deferral, UpdatePolicy: legacy.UpdatePolicy{ReviewOwnerID: r.UpdatePolicy.ReviewOwnerID,
				RequiresImpactDeclaration: r.UpdatePolicy.RequiresImpactDeclaration, RequiresProofBindingReview: r.UpdatePolicy.RequiresProofBindingReview},
		})
	}
	admitted, err := legacy.Evaluate(legacy.SourceValue(result))
	if err != nil || admitted.ExitCode != 0 {
		return legacy.Source{}, fmt.Errorf("reconstructed source rejected: %v %v", err, admitted.Failures)
	}
	return admitted.Source, nil
}

func sourceCompatRoundTrip(t testing.TB, source legacy.Source) model.Model {
	t.Helper()
	admitted := sourceCompatAdmit(t, legacy.SourceValue(source))
	candidate, err := model.Normalize(sourceCompatDraft(admitted))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := codec.Format(candidate)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := codec.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(candidate.Atomic(), reparsed.Model.Atomic()) || !reflect.DeepEqual(candidate.Layout(), reparsed.Model.Layout()) || !reflect.DeepEqual(candidate.References(), reparsed.Model.References()) {
		t.Fatal("private codec lost a complete owner projection")
	}
	restored, err := sourceCompatLegacy(reparsed.Model)
	if err != nil || !reflect.DeepEqual(restored, admitted) {
		t.Fatalf("whole canonical source correspondence failed: %v", err)
	}
	return reparsed.Model
}
