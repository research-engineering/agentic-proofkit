package app

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	sourceowner "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceCompatibilityCanonicalFieldInventory(t *testing.T) {
	for _, item := range []struct {
		value  any
		fields string
	}{
		{sourceowner.Requirement{}, "ClaimLevel Deferral ExternalNonClaimRefs Invariant Lifecycle NonClaimRefs NonClaims OwnerID ProofBindingRefs RequirementID RiskClass SharedPremises UpdatePolicy sourceReviewDigest"},
		{sourceowner.Lifecycle{}, "EvidenceRefs ReplacementRequirementIDs State"},
		{sourceowner.Deferral{}, "EvidenceRefs ExpiryRef MergePolicy OwnerID ReviewCondition RiskAcceptedBy"},
		{sourceowner.UpdatePolicy{}, "RequiresImpactDeclaration RequiresProofBindingReview ReviewOwnerID"},
	} {
		value := reflect.TypeOf(item.value)
		actual := []string{}
		for i := range value.NumField() {
			actual = append(actual, value.Field(i).Name)
		}
		slices.Sort(actual)
		if !slices.Equal(actual, strings.Fields(item.fields)) {
			t.Fatalf("%s fields changed; revise the complete mapping: %v", value.Name(), actual)
		}
	}
	source := sourceCompatSource(2)
	source.Requirements()[0].ClaimLevel = "deferred"
	source.Requirements()[0].Deferral = &sourceowner.Deferral{OwnerID: "owner.deferral", RiskAcceptedBy: "owner.risk", ReviewCondition: "Review the input.", ExpiryRef: "expiry.ref", MergePolicy: "merge.policy", EvidenceRefs: []string{"evidence/deferred.json"}}
	source.Requirements()[0].Lifecycle = sourceowner.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{source.Requirements()[1].RequirementID}}
	source.Requirements()[0].UpdatePolicy.RequiresImpactDeclaration = true
	source.Requirements()[0].UpdatePolicy.RequiresProofBindingReview = true
	wire, err := sourceowner.SourceValue(sourceCompatAdmit(t, sourceCompatValue(source)))
	if err != nil {
		t.Fatal(err)
	}
	group := wire["groups"].([]any)[0].(map[string]any)
	member := group["members"].([]any)[0].(map[string]any)
	fields := member["fields"].(map[string]any)
	for _, row := range []struct {
		value  map[string]any
		fields string
	}{
		{wire, "groups kind schemaVersion sourceId sourceNonClaims specPackagePath"},
		{group, "groupId members profileId sharedPremises statementStem"},
		{member, "fields requirementId statementCompletion"},
		{fields, "claimLevel deferral externalNonClaimRefs lifecycle nonClaimRefs nonClaims ownerId proofBindingRefs riskClass updatePolicy"},
		{fields["lifecycle"].(map[string]any), "evidenceRefs replacementRequirementIds state"},
		{fields["deferral"].(map[string]any), "evidenceRefs expiryRef mergePolicy ownerId reviewCondition riskAcceptedBy"},
		{fields["updatePolicy"].(map[string]any), "requiresImpactDeclaration requiresProofBindingReview reviewOwnerId"},
	} {
		keys := []string{}
		for key := range row.value {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, strings.Fields(row.fields)) {
			t.Fatalf("canonical wire fields changed: %v", keys)
		}
	}
}

func TestSourceCompatibilityAllFieldsAndVariants(t *testing.T) {
	for _, lifecycle := range []string{"active", "deprecated", "removed", "superseded"} {
		for _, claim := range []string{"advisory", "blocking", "deferred"} {
			if lifecycle != "active" && claim == "blocking" {
				continue // The source model forbids this combination.
			}
			for _, risk := range []string{"critical", "high", "low", "medium"} {
				t.Run(lifecycle+"/"+claim+"/"+risk, func(t *testing.T) {
					source := sourceCompatSource(2)
					r := &source.Requirements()[0]
					r.ClaimLevel, r.RiskClass, r.Lifecycle.State = claim, risk, lifecycle
					r.Invariant = "The value preserves\nUnicode \U0001f9ed and literal < & > delimiters."
					r.ExternalNonClaimRefs = []string{"external.alpha", "external.beta"}
					r.NonClaims = []string{"A direct denial remains independent.", "No execution is inferred."}
					r.ProofBindingRefs = []string{"proofkit/alpha.json", "proofkit/beta.json"}
					r.UpdatePolicy.RequiresImpactDeclaration, r.UpdatePolicy.RequiresProofBindingReview = true, true
					if lifecycle != "active" {
						r.Lifecycle.EvidenceRefs = []string{"evidence/lifecycle.json"}
					}
					if lifecycle == "superseded" {
						r.Lifecycle.ReplacementRequirementIDs = []string{source.Requirements()[1].RequirementID}
					}
					if claim == "deferred" {
						r.Deferral = &sourceowner.Deferral{OwnerID: "owner.deferral", RiskAcceptedBy: "owner.risk", ReviewCondition: "Review when the declared input changes.",
							ExpiryRef: "expiry.condition", MergePolicy: "policy.merge", EvidenceRefs: []string{"evidence/deferral.json"}}
					}
					sourceCompatRoundTrip(t, source)
				})
			}
		}
	}
	for _, impact := range []bool{false, true} {
		for _, binding := range []bool{false, true} {
			source := sourceCompatSource(1)
			source.Requirements()[0].UpdatePolicy.RequiresImpactDeclaration = impact
			source.Requirements()[0].UpdatePolicy.RequiresProofBindingReview = binding
			candidate := sourceCompatRoundTrip(t, source)
			got := candidate.Atomic().Requirements[0].UpdatePolicy
			if got.RequiresImpactDeclaration != impact || got.RequiresProofBindingReview != binding {
				t.Fatal("independent update-policy operands collapsed")
			}
		}
	}
	for _, count := range []int{0, 1, 4096, 4097} {
		sourceCompatRoundTrip(t, sourceCompatSource(count))
	}
}

func TestSourceCompatibilityRejectsPairedLifecycleContradictions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sourceCompatFixture)
	}{
		{"missing_proof_binding", func(s *sourceCompatFixture) {
			r := &s.Requirements()[0]
			r.ClaimLevel = "blocking"
			r.UpdatePolicy.RequiresImpactDeclaration = true
			r.UpdatePolicy.RequiresProofBindingReview = true
		}},
		{"impact_review_required", func(s *sourceCompatFixture) {
			r := &s.Requirements()[0]
			r.ClaimLevel = "blocking"
			r.ProofBindingRefs = []string{"proofkit/proof.json"}
			r.UpdatePolicy.RequiresProofBindingReview = true
		}},
		{"proof_binding_review_required", func(s *sourceCompatFixture) {
			r := &s.Requirements()[0]
			r.ClaimLevel = "blocking"
			r.ProofBindingRefs = []string{"proofkit/proof.json"}
			r.UpdatePolicy.RequiresImpactDeclaration = true
		}},
		{"missing_deferral", func(s *sourceCompatFixture) { s.Requirements()[0].ClaimLevel = "deferred" }},
		{"unexpected_deferral", func(s *sourceCompatFixture) {
			s.Requirements()[0].Deferral = &sourceowner.Deferral{OwnerID: "owner.deferral", RiskAcceptedBy: "owner.risk", ReviewCondition: "Review the input.", ExpiryRef: "expiry.ref", MergePolicy: "merge.policy", EvidenceRefs: []string{"evidence/deferred.json"}}
		}},
		{"missing_lifecycle_evidence", func(s *sourceCompatFixture) { s.Requirements()[0].Lifecycle.State = "deprecated" }},
		{"unexpected_replacement", func(s *sourceCompatFixture) {
			s.Requirements()[0].Lifecycle.ReplacementRequirementIDs = []string{s.Requirements()[1].RequirementID}
		}},
		{"missing_replacement", func(s *sourceCompatFixture) {
			s.Requirements()[0].Lifecycle = sourceowner.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}}
		}},
		{"self_replacement", func(s *sourceCompatFixture) {
			s.Requirements()[0].Lifecycle = sourceowner.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{s.Requirements()[0].RequirementID}}
		}},
		{"dangling_replacement", func(s *sourceCompatFixture) {
			s.Requirements()[0].Lifecycle = sourceowner.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{"REQ-MISSING"}}
		}},
		{"inactive_replacement", func(s *sourceCompatFixture) {
			s.Requirements()[0].Lifecycle = sourceowner.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{s.Requirements()[1].RequirementID}}
			s.Requirements()[1].Lifecycle = sourceowner.Lifecycle{State: "removed", EvidenceRefs: []string{"evidence/removal.json"}}
		}},
		{"nonactive_blocking_requirement", func(s *sourceCompatFixture) {
			r := &s.Requirements()[0]
			r.ClaimLevel = "blocking"
			r.ProofBindingRefs = []string{"proofkit/proof.json"}
			r.UpdatePolicy.RequiresImpactDeclaration = true
			r.UpdatePolicy.RequiresProofBindingReview = true
			r.Lifecycle = sourceowner.Lifecycle{State: "removed", EvidenceRefs: []string{"evidence/removal.json"}}
		}},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			source := sourceCompatSource(2)
			item.mutate(&source)
			raw := sourceCompatDecode(t, sourceCompatJSON(t, sourceCompatValue(source)))
			result, err := sourceowner.Evaluate(raw)
			if err != nil || result.ExitCode != 1 || result.Report.State != "failed" {
				t.Fatalf("semantic contradiction was not rejected: %v", err)
			}
			if _, admitted := result.Source.Model(); admitted {
				t.Fatal("failed source retained a usable model")
			}
			if _, err := model.Normalize(sourceCompatDraft(source)); model.ErrorCode(err) != item.name {
				t.Fatalf("candidate did not reject the intended contradiction: %v", err)
			}
			sourceCompatRoundTrip(t, sourceCompatSource(2))
		})
	}
}
