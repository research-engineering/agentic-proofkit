package app

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	legacy "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceCompatibilityCanonicalFieldInventory(t *testing.T) {
	for _, item := range []struct {
		value  any
		fields string
	}{
		{legacy.Source{}, "NonClaims OverviewPath Requirements RequirementsPath SourceID SpecPackagePath"},
		{legacy.Requirement{}, "ClaimLevel Deferral Invariant Lifecycle NonClaimRefs NonClaims OwnerID ProofBindingRefs RequirementID RiskClass UpdatePolicy"},
		{legacy.Lifecycle{}, "EvidenceRefs ReplacementRequirementIDs State"},
		{legacy.Deferral{}, "EvidenceRefs ExpiryRef MergePolicy OwnerID ReviewCondition RiskAcceptedBy"},
		{legacy.UpdatePolicy{}, "RequiresImpactDeclaration RequiresProofBindingReview ReviewOwnerID"},
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
	source := sourceCompatSource(1)
	source.Requirements[0].ClaimLevel = "deferred"
	source.Requirements[0].Deferral = &legacy.Deferral{OwnerID: "owner.deferral", RiskAcceptedBy: "owner.risk", ReviewCondition: "Review the input.", ExpiryRef: "expiry.ref", MergePolicy: "merge.policy", EvidenceRefs: []string{"evidence/deferred.json"}}
	wire := legacy.SourceValue(sourceCompatAdmit(t, legacy.SourceValue(source)))
	requirement := wire["requirements"].([]any)[0].(map[string]any)
	count := 0
	for _, row := range []struct {
		value  map[string]any
		fields string
	}{
		{wire, "nonClaims overviewPath requirements requirementsPath schemaVersion sourceId specPackagePath"},
		{requirement, "claimLevel deferral invariant lifecycle nonClaimRefs nonClaims ownerId proofBindingRefs requirementId riskClass updatePolicy"},
		{requirement["lifecycle"].(map[string]any), "evidenceRefs replacementRequirementIds state"},
		{requirement["deferral"].(map[string]any), "evidenceRefs expiryRef mergePolicy ownerId reviewCondition riskAcceptedBy"},
		{requirement["updatePolicy"].(map[string]any), "requiresImpactDeclaration requiresProofBindingReview reviewOwnerId"},
	} {
		keys := []string{}
		for key := range row.value {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, strings.Fields(row.fields)) {
			t.Fatalf("canonical wire fields changed: %v", keys)
		}
		count += len(keys)
	}
	if count != 30 {
		t.Fatalf("whole-source field inventory=%d, want30 including parent records", count)
	}
}

func TestSourceCompatibilityAllFieldsAndVariants(t *testing.T) {
	for _, lifecycle := range []string{"active", "deprecated", "removed", "superseded"} {
		for _, claim := range []string{"advisory", "blocking", "deferred"} {
			if lifecycle != "active" && claim == "blocking" {
				continue // This combination is independently forbidden by both owners.
			}
			for _, risk := range []string{"critical", "high", "low", "medium"} {
				t.Run(lifecycle+"/"+claim+"/"+risk, func(t *testing.T) {
					source := sourceCompatSource(2)
					r := &source.Requirements[0]
					r.ClaimLevel, r.RiskClass, r.Lifecycle.State = claim, risk, lifecycle
					r.Invariant = "The value preserves\nUnicode \U0001f9ed and literal < & > delimiters."
					r.NonClaimRefs = []string{"external.alpha", "external.beta"}
					r.NonClaims = []string{"A direct denial remains independent.", "No execution is inferred."}
					r.ProofBindingRefs = []string{"proofkit/alpha.json", "proofkit/beta.json"}
					r.UpdatePolicy.RequiresImpactDeclaration, r.UpdatePolicy.RequiresProofBindingReview = true, true
					if lifecycle != "active" {
						r.Lifecycle.EvidenceRefs = []string{"evidence/lifecycle.json"}
					}
					if lifecycle == "superseded" {
						r.Lifecycle.ReplacementRequirementIDs = []string{source.Requirements[1].RequirementID}
					}
					if claim == "deferred" {
						r.Deferral = &legacy.Deferral{OwnerID: "owner.deferral", RiskAcceptedBy: "owner.risk", ReviewCondition: "Review when the declared input changes.",
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
			source.Requirements[0].UpdatePolicy.RequiresImpactDeclaration = impact
			source.Requirements[0].UpdatePolicy.RequiresProofBindingReview = binding
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
		mutate func(*legacy.Source)
	}{
		{"missing_proof_binding", func(s *legacy.Source) {
			r := &s.Requirements[0]
			r.ClaimLevel = "blocking"
			r.UpdatePolicy.RequiresImpactDeclaration = true
			r.UpdatePolicy.RequiresProofBindingReview = true
		}},
		{"impact_review_required", func(s *legacy.Source) {
			r := &s.Requirements[0]
			r.ClaimLevel = "blocking"
			r.ProofBindingRefs = []string{"proofkit/proof.json"}
			r.UpdatePolicy.RequiresProofBindingReview = true
		}},
		{"proof_binding_review_required", func(s *legacy.Source) {
			r := &s.Requirements[0]
			r.ClaimLevel = "blocking"
			r.ProofBindingRefs = []string{"proofkit/proof.json"}
			r.UpdatePolicy.RequiresImpactDeclaration = true
		}},
		{"missing_deferral", func(s *legacy.Source) { s.Requirements[0].ClaimLevel = "deferred" }},
		{"unexpected_deferral", func(s *legacy.Source) {
			s.Requirements[0].Deferral = &legacy.Deferral{OwnerID: "owner.deferral", RiskAcceptedBy: "owner.risk", ReviewCondition: "Review the input.", ExpiryRef: "expiry.ref", MergePolicy: "merge.policy", EvidenceRefs: []string{"evidence/deferred.json"}}
		}},
		{"missing_lifecycle_evidence", func(s *legacy.Source) { s.Requirements[0].Lifecycle.State = "deprecated" }},
		{"unexpected_replacement", func(s *legacy.Source) {
			s.Requirements[0].Lifecycle.ReplacementRequirementIDs = []string{s.Requirements[1].RequirementID}
		}},
		{"missing_replacement", func(s *legacy.Source) {
			s.Requirements[0].Lifecycle = legacy.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}}
		}},
		{"self_replacement", func(s *legacy.Source) {
			s.Requirements[0].Lifecycle = legacy.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{s.Requirements[0].RequirementID}}
		}},
		{"dangling_replacement", func(s *legacy.Source) {
			s.Requirements[0].Lifecycle = legacy.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{"REQ-MISSING"}}
		}},
		{"inactive_replacement", func(s *legacy.Source) {
			s.Requirements[0].Lifecycle = legacy.Lifecycle{State: "superseded", EvidenceRefs: []string{"evidence/history.json"}, ReplacementRequirementIDs: []string{s.Requirements[1].RequirementID}}
			s.Requirements[1].Lifecycle = legacy.Lifecycle{State: "removed", EvidenceRefs: []string{"evidence/removal.json"}}
		}},
		{"nonactive_blocking_requirement", func(s *legacy.Source) {
			r := &s.Requirements[0]
			r.ClaimLevel = "blocking"
			r.ProofBindingRefs = []string{"proofkit/proof.json"}
			r.UpdatePolicy.RequiresImpactDeclaration = true
			r.UpdatePolicy.RequiresProofBindingReview = true
			r.Lifecycle = legacy.Lifecycle{State: "removed", EvidenceRefs: []string{"evidence/removal.json"}}
		}},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			source := sourceCompatSource(2)
			item.mutate(&source)
			raw := sourceCompatDecode(t, sourceCompatJSON(t, legacy.SourceValue(source)))
			result, err := legacy.Evaluate(raw)
			if err != nil || result.ExitCode != 1 || result.Report.State != "failed" {
				t.Fatalf("legacy semantic contradiction was not rejected: %v", err)
			}
			if _, err := model.Normalize(sourceCompatDraft(result.Source)); model.ErrorCode(err) != item.name {
				t.Fatalf("candidate did not reject the intended contradiction: %v", err)
			}
			sourceCompatRoundTrip(t, sourceCompatSource(2))
		})
	}
}
