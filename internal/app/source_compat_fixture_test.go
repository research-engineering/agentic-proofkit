package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	sourceowner "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
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

func sourceCompatAdmit(t testing.TB, raw any) sourceowner.Source {
	t.Helper()
	value := sourceCompatDecode(t, sourceCompatJSON(t, raw))
	result, err := sourceowner.Evaluate(value)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("source admission premise: err=%v failures=%v", err, result.Failures)
	}
	return result.Source
}

type sourceCompatProjection interface {
	SourceID() string
	SpecPackagePath() string
	OverviewPath() string
	RequirementsPath() string
	NonClaims() []string
	Requirements() []sourceowner.Requirement
}

// The compatibility fixture is intentionally editable input, never an admitted Source.
type sourceCompatFixture struct {
	sourceID, specPackagePath, overviewPath, requirementsPath string
	nonClaims                                                 []string
	requirements                                              []sourceowner.Requirement
}

func (source sourceCompatFixture) SourceID() string         { return source.sourceID }
func (source sourceCompatFixture) SpecPackagePath() string  { return source.specPackagePath }
func (source sourceCompatFixture) OverviewPath() string     { return source.overviewPath }
func (source sourceCompatFixture) RequirementsPath() string { return source.requirementsPath }
func (source sourceCompatFixture) NonClaims() []string      { return source.nonClaims }
func (source sourceCompatFixture) Requirements() []sourceowner.Requirement {
	return source.requirements
}

func sourceCompatValue(source sourceCompatProjection) map[string]any {
	stringsValue := func(values []string) []any {
		result := make([]any, len(values))
		for index, value := range values {
			result[index] = value
		}
		return result
	}
	groups := []any{}
	for i, r := range source.Requirements() {
		if i%model.DefaultLimits().MaxMembersPerGroup == 0 {
			groups = append(groups, map[string]any{
				"groupId": fmt.Sprintf("RGRP-COMPAT-%05d", len(groups)), "profileId": "",
				"statementStem": "", "sharedPremises": []any{}, "members": []any{},
			})
		}
		var deferral any
		if d := r.Deferral; d != nil {
			deferral = map[string]any{"ownerId": d.OwnerID, "riskAcceptedBy": d.RiskAcceptedBy,
				"reviewCondition": d.ReviewCondition, "expiryRef": d.ExpiryRef,
				"mergePolicy": d.MergePolicy, "evidenceRefs": stringsValue(d.EvidenceRefs)}
		}
		fields := map[string]any{
			"ownerId": r.OwnerID, "claimLevel": r.ClaimLevel, "riskClass": r.RiskClass,
			"nonClaims": stringsValue(r.NonClaims), "nonClaimRefs": stringsValue(r.NonClaimRefs),
			"externalNonClaimRefs": stringsValue(r.ExternalNonClaimRefs), "proofBindingRefs": stringsValue(r.ProofBindingRefs),
			"lifecycle": map[string]any{"state": r.Lifecycle.State, "evidenceRefs": stringsValue(r.Lifecycle.EvidenceRefs),
				"replacementRequirementIds": stringsValue(r.Lifecycle.ReplacementRequirementIDs)},
			"deferral": deferral, "updatePolicy": map[string]any{"reviewOwnerId": r.UpdatePolicy.ReviewOwnerID,
				"requiresImpactDeclaration":  r.UpdatePolicy.RequiresImpactDeclaration,
				"requiresProofBindingReview": r.UpdatePolicy.RequiresProofBindingReview},
		}
		group := groups[len(groups)-1].(map[string]any)
		group["members"] = append(group["members"].([]any), map[string]any{
			"requirementId": r.RequirementID, "statementCompletion": r.Invariant, "fields": fields,
		})
	}
	return map[string]any{
		"kind": "proofkit.requirement-source", "schemaVersion": json.Number("2"),
		"sourceId": source.SourceID(), "specPackagePath": source.SpecPackagePath(),
		"sourceNonClaims": stringsValue(source.NonClaims()), "groups": groups,
	}
}

func sourceCompatSource(count int) sourceCompatFixture {
	source := sourceCompatFixture{sourceID: "source.compatibility", specPackagePath: "docs/specs/compatibility",
		overviewPath: "docs/specs/compatibility/overview.md", requirementsPath: "docs/specs/compatibility/requirements.v2.json",
		nonClaims: []string{"Source compatibility does not prove execution."}, requirements: []sourceowner.Requirement{}}
	for i := range count {
		source.requirements = append(source.requirements, sourceowner.Requirement{
			RequirementID: fmt.Sprintf("REQ-COMPAT-%05d", i), OwnerID: "owner.requirement",
			Invariant: "The operation preserves its independently declared input.", ClaimLevel: "advisory", RiskClass: "low",
			Lifecycle: sourceowner.Lifecycle{State: "active"}, NonClaims: []string{"No native witness is asserted."},
			UpdatePolicy: sourceowner.UpdatePolicy{ReviewOwnerID: "owner.review"},
		})
	}
	return source
}

// This test-only mapping has no public converter or scenario-body authority.
func sourceCompatDraft(source sourceCompatProjection) model.Draft {
	draft := model.Draft{SourceID: source.SourceID(), SpecPackagePath: source.SpecPackagePath(), SourceNonClaims: source.NonClaims()}
	for i, r := range source.Requirements() {
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
			NonClaims: model.Own(r.NonClaims), ExternalNonClaimRefs: model.Own(r.ExternalNonClaimRefs), NonClaimRefs: model.Own(r.NonClaimRefs), ProofBindingRefs: model.Own(r.ProofBindingRefs),
			Lifecycle: model.Own(model.Lifecycle{State: model.LifecycleState(r.Lifecycle.State), EvidenceRefs: r.Lifecycle.EvidenceRefs, ReplacementRequirementIDs: r.Lifecycle.ReplacementRequirementIDs}),
			Deferral:  model.Own(deferral), UpdatePolicy: model.Own(model.UpdatePolicy{ReviewOwnerID: r.UpdatePolicy.ReviewOwnerID,
				RequiresImpactDeclaration: r.UpdatePolicy.RequiresImpactDeclaration, RequiresProofBindingReview: r.UpdatePolicy.RequiresProofBindingReview}),
		}}
		last := len(draft.Groups) - 1
		draft.Groups[last].Members = append(draft.Groups[last].Members, member)
	}
	return draft
}

func sourceCompatRestore(candidate model.Model) (sourceCompatFixture, error) {
	a := candidate.Atomic()
	if len(a.SourceNonClaimRefs)+len(a.NonClaimDefinitions)+len(a.Vocabulary)+len(a.Scenarios)+len(candidate.References().Derivations) != 0 {
		return sourceCompatFixture{}, fmt.Errorf("candidate has semantics outside the common domain")
	}
	result := sourceCompatFixture{sourceID: a.SourceID, specPackagePath: a.SpecPackagePath,
		overviewPath: a.SpecPackagePath + "/overview.md", requirementsPath: a.SpecPackagePath + "/requirements.v2.json",
		nonClaims: a.SourceNonClaims, requirements: []sourceowner.Requirement{}}
	for _, r := range a.Requirements {
		if len(r.SharedPremises)+len(r.NonClaimRefs) != 0 {
			return sourceCompatFixture{}, fmt.Errorf("candidate has requirement semantics outside the common domain")
		}
		var deferral *sourceowner.Deferral
		if r.Deferral != nil {
			d := r.Deferral
			deferral = &sourceowner.Deferral{OwnerID: d.OwnerID, RiskAcceptedBy: d.RiskAcceptedBy, ReviewCondition: d.ReviewCondition,
				ExpiryRef: d.ExpiryRef, MergePolicy: d.MergePolicy, EvidenceRefs: d.EvidenceRefs}
		}
		result.requirements = append(result.requirements, sourceowner.Requirement{
			RequirementID: r.RequirementID, Invariant: r.Invariant, OwnerID: r.OwnerID, ClaimLevel: string(r.ClaimLevel), RiskClass: string(r.RiskClass),
			ExternalNonClaimRefs: r.ExternalNonClaimRefs, NonClaims: r.NonClaims, ProofBindingRefs: r.ProofBindingRefs,
			Lifecycle: sourceowner.Lifecycle{State: string(r.Lifecycle.State), EvidenceRefs: r.Lifecycle.EvidenceRefs, ReplacementRequirementIDs: r.Lifecycle.ReplacementRequirementIDs},
			Deferral:  deferral, UpdatePolicy: sourceowner.UpdatePolicy{ReviewOwnerID: r.UpdatePolicy.ReviewOwnerID,
				RequiresImpactDeclaration: r.UpdatePolicy.RequiresImpactDeclaration, RequiresProofBindingReview: r.UpdatePolicy.RequiresProofBindingReview},
		})
	}
	return result, nil
}

func sourceCompatRoundTrip(t testing.TB, source sourceCompatProjection) model.Model {
	t.Helper()
	admitted := sourceCompatAdmit(t, sourceCompatValue(source))
	candidate, err := model.Normalize(sourceCompatDraft(source))
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := admitted.Model()
	if !ok || !reflect.DeepEqual(actual.Atomic(), candidate.Atomic()) || !reflect.DeepEqual(actual.Layout(), candidate.Layout()) || !reflect.DeepEqual(actual.References(), candidate.References()) {
		t.Fatal("public admission disagrees with the independently authored common-domain mapping")
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
		t.Fatal("codec lost a complete owner projection")
	}
	restored, err := sourceCompatRestore(reparsed.Model)
	if err != nil || !reflect.DeepEqual(sourceCompatValue(restored), sourceCompatValue(source)) || restored.OverviewPath() != source.OverviewPath() || restored.RequirementsPath() != source.RequirementsPath() {
		t.Fatalf("whole canonical source correspondence failed: %v", err)
	}
	return reparsed.Model
}
