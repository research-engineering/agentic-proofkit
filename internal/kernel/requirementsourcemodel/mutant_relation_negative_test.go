package requirementsourcemodel

import "testing"

func TestMutantRelationPredicatesRejectNearMisses(t *testing.T) {
	tests := []struct {
		relationID mutantRelationID
		mutantID   string
		breaks     []func(Draft, *Draft)
	}{
		{relationClaimDeferralPresence, "metadata-deferral-presence", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Groups[1].Members[0].Fields.ClaimLevel = before.Groups[1].Members[0].Fields.ClaimLevel
		}}},
		{relationGroupIdentityMemberReference, "group-id", []func(Draft, *Draft){func(_ Draft, after *Draft) {
			after.Groups[0].Members[0], after.Groups[0].Members[1] = after.Groups[0].Members[1], after.Groups[0].Members[0]
		}}},
		{relationGroupMemberReassignment, "group-membership", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Groups[1].Members[0] = before.Groups[1].Members[0]
		}}},
		{relationLifecycleStateEvidence, "metadata-lifecycle-state", []func(Draft, *Draft){
			func(_ Draft, after *Draft) {
				lifecycle := after.Groups[1].Members[0].Fields.Lifecycle.Value
				lifecycle.EvidenceRefs = nil
				after.Groups[1].Members[0].Fields.Lifecycle.Value = lifecycle
			},
			func(_ Draft, after *Draft) {
				lifecycle := after.Groups[1].Members[0].Fields.Lifecycle.Value
				lifecycle.ReplacementRequirementIDs = []string{"REQ-MODEL-001"}
				after.Groups[1].Members[0].Fields.Lifecycle.Value = lifecycle
			},
		}},
		{relationNonClaimReferenceRename, "nonclaim-id", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.SourceNonClaimRefs[0] = before.SourceNonClaimRefs[0]
		}}},
		{relationObjectFormatCommitIdentity, "derivation-object-format", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Derivations[0].SourceRef.CommitOID = before.Derivations[0].SourceRef.CommitOID
		}}},
		{relationProfileReferenceRename, "profile-id", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Groups[0].ProfileID = before.Groups[0].ProfileID
		}}},
		{relationProfileRemovalOwnershipMigration, "group-profile-ref", []func(Draft, *Draft){func(_ Draft, after *Draft) {
			after.Groups[0].Members[0].Fields.OwnerID = Field[string]{}
		}}},
		{relationRequirementReferenceRename, "member-id", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Derivations[0].RequirementIDs = cloneStrings(before.Derivations[0].RequirementIDs)
		}, func(_ Draft, after *Draft) {
			after.Derivations[0].RequirementIDs = append(after.Derivations[0].RequirementIDs, "REQ-MODEL-003")
		}, func(_ Draft, after *Draft) {
			lifecycle := after.Groups[2].Members[0].Fields.Lifecycle.Value
			lifecycle.ReplacementRequirementIDs = append(lifecycle.ReplacementRequirementIDs, "REQ-MODEL-005")
			after.Groups[2].Members[0].Fields.Lifecycle.Value = lifecycle
		}}},
		{relationScenarioParameterRename, "scenario-parameters", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Scenarios[0].Preconditions = cloneStrings(before.Scenarios[0].Preconditions)
		}, func(_ Draft, after *Draft) {
			after.Scenarios[0].Examples[0].Values["channel"] = "rewritten"
		}, func(_ Draft, after *Draft) {
			after.Scenarios[0].ActionSequence[0] = "Submit a ${channel} request."
		}, func(_ Draft, after *Draft) {
			after.Scenarios[0].ExpectedObservations[0] = "The ${channel} request is accepted."
		}, func(_ Draft, after *Draft) {
			after.Scenarios[0].ForbiddenObservations[0] = "The ${channel} service exposes a secret."
		}}},
		{relationScenarioVocabularyExtension, "scenario-vocabulary", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Scenarios[0].VocabularyRefs = cloneStrings(before.Scenarios[0].VocabularyRefs)
		}, func(_ Draft, after *Draft) {
			after.Vocabulary[0].Definition = "A changed existing definition."
		}}},
		{relationVocabularyReferenceRename, "vocabulary-id", []func(Draft, *Draft){func(before Draft, after *Draft) {
			after.Scenarios[0].VocabularyRefs = cloneStrings(before.Scenarios[0].VocabularyRefs)
		}}},
	}
	registry := mutantRelationRegistry()
	if len(tests) != len(registry) {
		t.Fatalf("negative relation cases = %d, registry = %d", len(tests), len(registry))
	}
	seen := map[mutantRelationID]struct{}{}
	for _, test := range tests {
		t.Run(string(test.relationID), func(t *testing.T) {
			relation, exists := registry[test.relationID]
			if !exists {
				t.Fatalf("unknown relation %q", test.relationID)
			}
			if _, duplicate := seen[test.relationID]; duplicate {
				t.Fatalf("duplicate negative relation case %q", test.relationID)
			}
			seen[test.relationID] = struct{}{}
			before := validDraft()
			after := cloneDraft(before)
			if !applyMutant(test.mutantID, &after) || !relation.holds(before, after) {
				t.Fatalf("coordinated mutant %q does not satisfy relation %q", test.mutantID, test.relationID)
			}
			for index, breakRelation := range test.breaks {
				nearMiss := cloneDraft(after)
				breakRelation(before, &nearMiss)
				if relation.holds(before, nearMiss) {
					t.Fatalf("relation %q accepted near miss %d", test.relationID, index)
				}
			}
			contaminated := cloneDraft(after)
			contaminated.SpecPackagePath = "docs/specs/contaminated"
			if relation.holds(before, contaminated) {
				t.Fatalf("relation %q accepted an unrelated draft change", test.relationID)
			}
		})
	}
}
