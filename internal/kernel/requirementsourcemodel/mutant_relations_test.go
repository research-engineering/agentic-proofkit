package requirementsourcemodel

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

type mutantRelation struct {
	fields []string
	holds  func(Draft, Draft) bool
}

type mutantRelationID string

const (
	relationClaimDeferralPresence            mutantRelationID = "claim-deferral-presence"
	relationGroupIdentityMemberReference     mutantRelationID = "group-identity-member-reference"
	relationGroupMemberReassignment          mutantRelationID = "group-member-reassignment"
	relationLifecycleStateEvidence           mutantRelationID = "lifecycle-state-evidence"
	relationNonClaimReferenceRename          mutantRelationID = "nonclaim-reference-rename"
	relationObjectFormatCommitIdentity       mutantRelationID = "object-format-commit-identity"
	relationProfileReferenceRename           mutantRelationID = "profile-reference-rename"
	relationProfileRemovalOwnershipMigration mutantRelationID = "profile-removal-ownership-migration"
	relationRequirementReferenceRename       mutantRelationID = "requirement-reference-rename"
	relationScenarioParameterRename          mutantRelationID = "scenario-parameter-rename"
	relationScenarioVocabularyExtension      mutantRelationID = "scenario-vocabulary-extension"
	relationVocabularyReferenceRename        mutantRelationID = "vocabulary-reference-rename"
)

func mutantRelationRegistry() map[mutantRelationID]mutantRelation {
	return map[mutantRelationID]mutantRelation{
		relationClaimDeferralPresence: {
			fields: []string{"metadata.claimLevel", "metadata.deferral.evidenceRefs", "metadata.deferral.expiryRef", "metadata.deferral.mergePolicy", "metadata.deferral.ownerId", "metadata.deferral.presence", "metadata.deferral.reviewCondition", "metadata.deferral.riskAcceptedBy"},
			holds: func(before Draft, after Draft) bool {
				left := before.Groups[1].Members[0].Fields
				right := after.Groups[1].Members[0].Fields
				if left.ClaimLevel.Value != ClaimDeferred || left.Deferral.Value == nil || right.ClaimLevel.Value == ClaimDeferred || !right.Deferral.Present || right.Deferral.Value != nil {
					return false
				}
				expected := cloneDraft(before)
				expected.Groups[1].Members[0].Fields.ClaimLevel = right.ClaimLevel
				expected.Groups[1].Members[0].Fields.Deferral = right.Deferral
				return reflect.DeepEqual(after, expected)
			},
		},
		relationGroupIdentityMemberReference: {
			fields: []string{"group.id", "group.memberRefs"},
			holds: func(before Draft, after Draft) bool {
				expected := cloneDraft(before)
				expected.Groups[0].GroupID = "RGRP-MODEL-REQUESTS-V2"
				return reflect.DeepEqual(after, expected)
			},
		},
		relationGroupMemberReassignment: {
			fields: []string{"group.memberRefs"},
			holds: func(before Draft, after Draft) bool {
				expected := cloneDraft(before)
				expected.Groups[1].Members[0], expected.Groups[2].Members[0] = expected.Groups[2].Members[0], expected.Groups[1].Members[0]
				return reflect.DeepEqual(after, expected)
			},
		},

		relationLifecycleStateEvidence: {
			fields: []string{"metadata.lifecycle.evidenceRefs", "metadata.lifecycle.state"},
			holds: func(before Draft, after Draft) bool {
				left := before.Groups[1].Members[0].Fields.Lifecycle.Value
				right := after.Groups[1].Members[0].Fields.Lifecycle.Value
				if left.State == right.State || len(left.EvidenceRefs) != 0 || len(right.EvidenceRefs) == 0 {
					return false
				}
				expected := cloneDraft(before)
				lifecycle := expected.Groups[1].Members[0].Fields.Lifecycle.Value
				lifecycle.State = right.State
				lifecycle.EvidenceRefs = cloneStrings(right.EvidenceRefs)
				expected.Groups[1].Members[0].Fields.Lifecycle.Value = lifecycle
				return reflect.DeepEqual(after, expected)
			},
		},
		relationNonClaimReferenceRename: {
			fields: []string{"nonClaim.id", "source.nonClaimRefs"},
			holds: func(before Draft, after Draft) bool {
				oldID := before.NonClaimDefinitions[0].NonClaimID
				newID := after.NonClaimDefinitions[0].NonClaimID
				if oldID == newID || after.SourceNonClaimRefs[0] != newID {
					return false
				}
				expected := cloneDraft(before)
				expected.NonClaimDefinitions[0].NonClaimID = newID
				expected.SourceNonClaimRefs[0] = newID
				return reflect.DeepEqual(expected, after)
			},
		},
		relationObjectFormatCommitIdentity: {
			fields: []string{"derivation.sourceRef.commitOid", "derivation.sourceRef.objectFormat"},
			holds: func(before Draft, after Draft) bool {
				left := before.Derivations[0].SourceRef
				right := after.Derivations[0].SourceRef
				if left.ObjectFormat == right.ObjectFormat || right.ObjectFormat != ObjectSHA256 || len(right.CommitOID) != 64 {
					return false
				}
				expected := cloneDraft(before)
				expected.Derivations[0].SourceRef.ObjectFormat = right.ObjectFormat
				expected.Derivations[0].SourceRef.CommitOID = right.CommitOID
				return reflect.DeepEqual(after, expected)
			},
		},
		relationProfileReferenceRename: {
			fields: []string{"group.profileRef", "profile.id"},
			holds: func(before Draft, after Draft) bool {
				oldID := before.Profiles[0].ProfileID
				newID := after.Profiles[0].ProfileID
				if oldID == newID {
					return false
				}
				expected := cloneDraft(before)
				expected.Profiles[0].ProfileID = newID
				replaceProfileReferences(expected.Groups, oldID, newID)
				return reflect.DeepEqual(after, expected)
			},
		},
		relationProfileRemovalOwnershipMigration: {
			fields: []string{"group.profileRef", "metadata.claimLevel", "metadata.ownerId", "metadata.riskClass", "metadata.updatePolicy.requiresImpactDeclaration", "metadata.updatePolicy.requiresProofBindingReview", "metadata.updatePolicy.reviewOwnerId", "profile.id"},
			holds: func(before Draft, after Draft) bool {
				if len(before.Profiles) != 1 || len(after.Profiles) != 0 || after.Groups[0].ProfileID != "" {
					return false
				}
				expected := cloneDraft(before)
				removeProfileWithoutChangingSemantics(&expected)
				if !reflect.DeepEqual(after, expected) {
					return false
				}
				left, leftErr := Normalize(before)
				right, rightErr := Normalize(after)
				return leftErr == nil && rightErr == nil && reflect.DeepEqual(left.Atomic(), right.Atomic())
			},
		},
		relationRequirementReferenceRename: {
			fields: []string{"derivation.requirementIds", "group.memberRefs", "member.requirementId"},
			holds: func(before Draft, after Draft) bool {
				oldID := before.Groups[0].Members[1].RequirementID
				newID := after.Groups[0].Members[1].RequirementID
				if oldID == newID {
					return false
				}
				expected := cloneDraft(before)
				replaceRequirementMemberAndDerivationReferences(&expected, oldID, newID)
				return reflect.DeepEqual(after, expected)
			},
		},
		relationScenarioParameterRename: {
			fields: []string{"scenario.example.values", "scenario.parameters", "scenario.preconditions"},
			holds: func(before Draft, after Draft) bool {
				oldParameter, newParameter, ok := singleParameterRename(before.Scenarios[0].Parameters, after.Scenarios[0].Parameters)
				if !ok {
					return false
				}
				expected := cloneDraft(before)
				renameScenarioParameter(&expected.Scenarios[0], oldParameter, newParameter)
				return reflect.DeepEqual(after, expected)
			},
		},
		relationScenarioVocabularyExtension: {
			fields: []string{"scenario.vocabularyRefs", "vocabulary.definition", "vocabulary.id", "vocabulary.kind", "vocabulary.label"},
			holds: func(before Draft, after Draft) bool {
				added, ok := singleAddedVocabularyTerm(before.Vocabulary, after.Vocabulary)
				if !ok {
					return false
				}
				expected := cloneDraft(before)
				expected.Vocabulary = append(expected.Vocabulary, added)
				expected.Scenarios[0].VocabularyRefs = append(expected.Scenarios[0].VocabularyRefs, added.TermID)
				sort.Strings(expected.Scenarios[0].VocabularyRefs)
				return reflect.DeepEqual(after, expected)
			},
		},
		relationVocabularyReferenceRename: {
			fields: []string{"scenario.vocabularyRefs", "vocabulary.id"},
			holds: func(before Draft, after Draft) bool {
				oldID := before.Vocabulary[0].TermID
				newID := after.Vocabulary[0].TermID
				if oldID == newID {
					return false
				}
				expected := cloneDraft(before)
				expected.Vocabulary[0].TermID = newID
				for index := range expected.Scenarios {
					replaceStringReferences(expected.Scenarios[index].VocabularyRefs, oldID, newID)
				}
				return reflect.DeepEqual(after, expected)
			},
		},
	}
}

func replaceProfileReferences(groups []Group, oldID string, newID string) {
	for index := range groups {
		if groups[index].ProfileID == oldID {
			groups[index].ProfileID = newID
		}
	}
}

func replaceRequirementMemberAndDerivationReferences(draft *Draft, oldID string, newID string) {
	for groupIndex := range draft.Groups {
		for memberIndex := range draft.Groups[groupIndex].Members {
			member := &draft.Groups[groupIndex].Members[memberIndex]
			if member.RequirementID == oldID {
				member.RequirementID = newID
			}
		}
	}
	for index := range draft.Derivations {
		replaceStringReferences(draft.Derivations[index].RequirementIDs, oldID, newID)
	}
}

func replaceStringReferences(values []string, oldID string, newID string) {
	for index := range values {
		if values[index] == oldID {
			values[index] = newID
		}
	}
}

func singleParameterRename(before []string, after []string) (string, string, bool) {
	if len(before) != len(after) {
		return "", "", false
	}
	beforeSet := make(map[string]struct{}, len(before))
	afterSet := make(map[string]struct{}, len(after))
	for _, value := range before {
		beforeSet[value] = struct{}{}
	}
	for _, value := range after {
		afterSet[value] = struct{}{}
	}
	removed := ""
	added := ""
	for value := range beforeSet {
		if _, exists := afterSet[value]; !exists {
			if removed != "" {
				return "", "", false
			}
			removed = value
		}
	}
	for value := range afterSet {
		if _, exists := beforeSet[value]; !exists {
			if added != "" {
				return "", "", false
			}
			added = value
		}
	}
	return removed, added, removed != "" && added != ""
}

func renameScenarioParameter(scenario *Scenario, oldParameter string, newParameter string) {
	replaceStringReferences(scenario.Parameters, oldParameter, newParameter)
	sort.Strings(scenario.Parameters)
	for index := range scenario.Preconditions {
		scenario.Preconditions[index] = strings.ReplaceAll(scenario.Preconditions[index], "${"+oldParameter+"}", "${"+newParameter+"}")
	}
	for index := range scenario.Examples {
		value, exists := scenario.Examples[index].Values[oldParameter]
		if !exists {
			continue
		}
		delete(scenario.Examples[index].Values, oldParameter)
		scenario.Examples[index].Values[newParameter] = value
	}
}

func singleAddedVocabularyTerm(before []VocabularyTerm, after []VocabularyTerm) (VocabularyTerm, bool) {
	if len(after) != len(before)+1 {
		return VocabularyTerm{}, false
	}
	beforeByID := make(map[string]VocabularyTerm, len(before))
	for _, term := range before {
		beforeByID[term.TermID] = term
	}
	added := VocabularyTerm{}
	found := false
	for _, term := range after {
		baseline, exists := beforeByID[term.TermID]
		if exists {
			if !reflect.DeepEqual(term, baseline) {
				return VocabularyTerm{}, false
			}
			continue
		}
		if found {
			return VocabularyTerm{}, false
		}
		added = term
		found = true
	}
	return added, found
}

func validateMutantRelations(record mutantRecord, before Draft, after Draft) error {
	registry := mutantRelationRegistry()
	for _, relationID := range record.RelationIDs {
		relation, exists := registry[mutantRelationID(relationID)]
		if !exists {
			return fmt.Errorf("unknown relation %q", relationID)
		}
		if !reflect.DeepEqual(relation.fields, record.MutatedFields) {
			return fmt.Errorf("relation %q fields %v do not match %v", relationID, relation.fields, record.MutatedFields)
		}
		if !relation.holds(before, after) {
			return fmt.Errorf("relation %q predicate is false", relationID)
		}
	}
	return nil
}
