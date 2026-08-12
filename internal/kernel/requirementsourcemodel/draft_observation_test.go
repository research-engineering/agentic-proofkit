package requirementsourcemodel

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

type keyedDraftValue struct {
	identity string
	value    any
}

type keyedDraftObservation struct {
	identities       []string
	valuesByIdentity map[string]string
	valueMultiset    []string
}

type draftMetadataValue struct {
	OwnerKind MetadataOwnerKind
	Present   bool
	Value     any
}

func changedDraftFieldIDs(before Draft, after Draft, fields map[string][]string) []string {
	changed := []string{}
	for fieldID := range fields {
		left, leftHandled := observeDraftField(before, fieldID)
		right, rightHandled := observeDraftField(after, fieldID)
		if !leftHandled || !rightHandled {
			panic("unhandled draft field: " + fieldID)
		}
		if !draftFieldObservationsEqual(left, right) {
			changed = append(changed, fieldID)
		}
	}
	sort.Strings(changed)
	return changed
}

func observeDraftField(draft Draft, fieldID string) (any, bool) {
	switch fieldID {
	case "source.id":
		return draft.SourceID, true
	case "source.specPackagePath":
		return draft.SpecPackagePath, true
	case "source.nonClaimRefs":
		return sortedObservationStrings(draft.SourceNonClaimRefs), true
	case "nonClaim.id":
		return projectIdentities(draft.NonClaimDefinitions, func(value NonClaimDefinition) string { return value.NonClaimID }), true
	case "nonClaim.statement":
		return projectKeyedValues(draft.NonClaimDefinitions, func(value NonClaimDefinition) string { return value.NonClaimID }, func(value NonClaimDefinition) any { return value.Statement }), true
	case "vocabulary.id":
		return projectIdentities(draft.Vocabulary, func(value VocabularyTerm) string { return value.TermID }), true
	case "vocabulary.kind":
		return projectKeyedValues(draft.Vocabulary, func(value VocabularyTerm) string { return value.TermID }, func(value VocabularyTerm) any { return value.Kind }), true
	case "vocabulary.label":
		return projectKeyedValues(draft.Vocabulary, func(value VocabularyTerm) string { return value.TermID }, func(value VocabularyTerm) any { return value.Label }), true
	case "vocabulary.definition":
		return projectKeyedValues(draft.Vocabulary, func(value VocabularyTerm) string { return value.TermID }, func(value VocabularyTerm) any { return value.Definition }), true
	case "derivation.id":
		return projectIdentities(draft.Derivations, func(value Derivation) string { return value.DerivationID }), true
	case "derivation.sourceKind":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.SourceKind }), true
	case "derivation.sourceRef.objectFormat":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.SourceRef.ObjectFormat }), true
	case "derivation.sourceRef.commitOid":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.SourceRef.CommitOID }), true
	case "derivation.sourceRef.path":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.SourceRef.Path }), true
	case "derivation.sourceRef.sha256":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.SourceRef.SHA256 }), true
	case "derivation.selector.start":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.Selector.Start }), true
	case "derivation.selector.end":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return value.Selector.End }), true
	case "derivation.requirementIds":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return sortedObservationStrings(value.RequirementIDs) }), true
	case "derivation.nonClaimRefs":
		return projectKeyedValues(draft.Derivations, derivationIdentity, func(value Derivation) any { return sortedObservationStrings(value.NonClaimRefs) }), true
	case "profile.id":
		return projectIdentities(draft.Profiles, func(value Profile) string { return value.ProfileID }), true
	case "group.id":
		return projectIdentities(draft.Groups, func(value Group) string { return value.GroupID }), true
	case "group.memberRefs":
		return projectGroupMemberReferences(draft), true
	case "group.profileRef":
		return projectKeyedValues(draft.Groups, groupIdentity, func(value Group) any { return value.ProfileID }), true
	case "group.statementStem":
		return projectKeyedValues(draft.Groups, groupIdentity, func(value Group) any { return value.StatementStem }), true
	case "group.sharedPremises":
		return projectKeyedValues(draft.Groups, groupIdentity, func(value Group) any { return sortedObservationStrings(value.SharedPremises) }), true
	case "member.requirementId":
		return projectDraftMemberIdentities(draft), true
	case "member.statementCompletion":
		return projectDraftMembers(draft, func(value Member) any { return value.StatementCompletion }), true
	case "scenario.id":
		return projectIdentities(draft.Scenarios, func(value Scenario) string { return value.ScenarioID }), true
	case "scenario.requirementIds":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.RequirementIDs) }), true
	case "scenario.parameters":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.Parameters) }), true
	case "scenario.preconditions":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.Preconditions) }), true
	case "scenario.actionSequence":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return value.ActionSequence }), true
	case "scenario.expectedObservations":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.ExpectedObservations) }), true
	case "scenario.forbiddenObservations":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.ForbiddenObservations) }), true
	case "scenario.example.id":
		return projectDraftExampleIdentities(draft), true
	case "scenario.example.values":
		return projectDraftExamples(draft, func(value Example) any { return value.Values }), true
	case "scenario.vocabularyRefs":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.VocabularyRefs) }), true
	case "scenario.nonClaimRefs":
		return projectKeyedValues(draft.Scenarios, scenarioIdentity, func(value Scenario) any { return sortedObservationStrings(value.NonClaimRefs) }), true
	}
	if stringsHasPrefix(fieldID, "metadata.") {
		return observeDraftMetadata(draft, fieldID), true
	}
	return nil, false
}

func draftFieldObservationsEqual(left any, right any) bool {
	leftKeyed, leftIsKeyed := left.(keyedDraftObservation)
	rightKeyed, rightIsKeyed := right.(keyedDraftObservation)
	if leftIsKeyed != rightIsKeyed {
		return false
	}
	if !leftIsKeyed {
		return reflect.DeepEqual(left, right)
	}
	if reflect.DeepEqual(leftKeyed.identities, rightKeyed.identities) {
		return reflect.DeepEqual(leftKeyed.valuesByIdentity, rightKeyed.valuesByIdentity)
	}
	return reflect.DeepEqual(leftKeyed.valueMultiset, rightKeyed.valueMultiset)
}

func projectIdentities[T any](values []T, identity func(T) string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = identity(value)
	}
	sort.Strings(result)
	return result
}

func projectKeyedValues[T any](values []T, identity func(T) string, project func(T) any) keyedDraftObservation {
	entries := make([]keyedDraftValue, len(values))
	for index, value := range values {
		entries[index] = keyedDraftValue{identity: identity(value), value: project(value)}
	}
	return newKeyedDraftObservation(entries)
}

func projectDraftMemberIdentities(draft Draft) []string {
	result := []string{}
	for _, group := range draft.Groups {
		for _, member := range group.Members {
			result = append(result, member.RequirementID)
		}
	}
	sort.Strings(result)
	return result
}

func projectGroupMemberReferences(draft Draft) []string {
	result := []string{}
	for _, group := range draft.Groups {
		for _, member := range group.Members {
			result = append(result, group.GroupID+"\x00"+member.RequirementID)
		}
	}
	sort.Strings(result)
	return result
}

func projectDraftMembers(draft Draft, project func(Member) any) keyedDraftObservation {
	entries := []keyedDraftValue{}
	for _, group := range draft.Groups {
		for _, member := range group.Members {
			entries = append(entries, keyedDraftValue{identity: member.RequirementID, value: project(member)})
		}
	}
	return newKeyedDraftObservation(entries)
}

func projectDraftExampleIdentities(draft Draft) []string {
	result := []string{}
	for _, scenario := range draft.Scenarios {
		for _, example := range scenario.Examples {
			result = append(result, example.ExampleID)
		}
	}
	sort.Strings(result)
	return result
}

func projectDraftExamples(draft Draft, project func(Example) any) keyedDraftObservation {
	entries := []keyedDraftValue{}
	for _, scenario := range draft.Scenarios {
		for _, example := range scenario.Examples {
			identity := scenario.ScenarioID + "\x00" + example.ExampleID
			entries = append(entries, keyedDraftValue{identity: identity, value: project(example)})
		}
	}
	return newKeyedDraftObservation(entries)
}

func newKeyedDraftObservation(entries []keyedDraftValue) keyedDraftObservation {
	result := keyedDraftObservation{
		identities:       make([]string, 0, len(entries)),
		valuesByIdentity: make(map[string]string, len(entries)),
		valueMultiset:    make([]string, 0, len(entries)),
	}
	for _, entry := range entries {
		encoded, err := json.Marshal(entry.value)
		if err != nil {
			panic(err)
		}
		value := string(encoded)
		if _, duplicate := result.valuesByIdentity[entry.identity]; duplicate {
			panic("duplicate observation identity: " + entry.identity)
		}
		result.identities = append(result.identities, entry.identity)
		result.valuesByIdentity[entry.identity] = value
		result.valueMultiset = append(result.valueMultiset, value)
	}
	sort.Strings(result.identities)
	sort.Strings(result.valueMultiset)
	return result
}

func observeDraftMetadata(draft Draft, fieldID string) keyedDraftObservation {
	entries := []keyedDraftValue{}
	for _, profile := range draft.Profiles {
		present, value := metadataFieldValue(profile.Fields, fieldID)
		if present && deferralSubfieldExists(profile.Fields, fieldID) {
			entries = append(entries, keyedDraftValue{
				identity: "profile:" + profile.ProfileID,
				value:    draftMetadataValue{OwnerKind: MetadataOwnerProfile, Present: present, Value: value},
			})
		}
	}
	for _, group := range draft.Groups {
		for _, member := range group.Members {
			present, value := metadataFieldValue(member.Fields, fieldID)
			if present && deferralSubfieldExists(member.Fields, fieldID) {
				entries = append(entries, keyedDraftValue{
					identity: "member:" + member.RequirementID,
					value:    draftMetadataValue{OwnerKind: MetadataOwnerMember, Present: present, Value: value},
				})
			}
		}
	}
	return newKeyedDraftObservation(entries)
}

func derivationIdentity(value Derivation) string { return value.DerivationID }

func groupIdentity(value Group) string { return value.GroupID }

func scenarioIdentity(value Scenario) string { return value.ScenarioID }

func sortedObservationStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func TestChangedDraftFieldIDsIsIdentityAware(t *testing.T) {
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	fields := make(map[string][]string, len(manifest.Fields))
	for _, field := range manifest.Fields {
		fields[field.FieldID] = field.RequiredProjections
	}

	baseline := validDraft()
	permuted := cloneDraft(baseline)
	reverseDefinitions(permuted.NonClaimDefinitions)
	if changed := changedDraftFieldIDs(baseline, permuted, fields); len(changed) != 0 {
		t.Fatalf("set permutation changed fields %v", changed)
	}

	baseline.NonClaimDefinitions = append(baseline.NonClaimDefinitions, NonClaimDefinition{
		NonClaimID: "NCL-MODEL-005",
		Statement:  "A fifth bounded non-claim.",
	})
	baseline.SourceNonClaimRefs = append(baseline.SourceNonClaimRefs, "NCL-MODEL-005")
	swapped := cloneDraft(baseline)
	swapped.NonClaimDefinitions[0].NonClaimID, swapped.NonClaimDefinitions[4].NonClaimID =
		swapped.NonClaimDefinitions[4].NonClaimID, swapped.NonClaimDefinitions[0].NonClaimID
	changed := changedDraftFieldIDs(baseline, swapped, fields)
	want := []string{"nonClaim.statement"}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("identity reassignment changed fields %v, want %v", changed, want)
	}

	moved := cloneDraft(validDraft())
	moved.Groups[1].Members[0], moved.Groups[2].Members[0] = moved.Groups[2].Members[0], moved.Groups[1].Members[0]
	changed = changedDraftFieldIDs(validDraft(), moved, fields)
	want = []string{"group.memberRefs"}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("group membership reassignment changed fields %v, want %v", changed, want)
	}
}

func deferralSubfieldExists(fields MetadataFields, fieldID string) bool {
	return fieldID == "metadata.deferral.presence" || !stringsHasPrefix(fieldID, "metadata.deferral.") || fields.Deferral.Value != nil
}
