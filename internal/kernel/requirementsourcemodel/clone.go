package requirementsourcemodel

func cloneDraft(value Draft) Draft {
	profiles := make([]Profile, len(value.Profiles))
	for index, profile := range value.Profiles {
		profiles[index] = Profile{ProfileID: profile.ProfileID, Fields: cloneMetadataFields(profile.Fields)}
	}
	groups := make([]Group, len(value.Groups))
	for index, group := range value.Groups {
		groups[index] = cloneGroup(group)
	}
	derivations := make([]Derivation, len(value.Derivations))
	for index, derivation := range value.Derivations {
		derivations[index] = cloneDerivation(derivation)
	}
	return Draft{
		SourceID:            value.SourceID,
		SpecPackagePath:     value.SpecPackagePath,
		SourceNonClaimRefs:  cloneStrings(value.SourceNonClaimRefs),
		NonClaimDefinitions: append([]NonClaimDefinition(nil), value.NonClaimDefinitions...),
		Vocabulary:          append([]VocabularyTerm(nil), value.Vocabulary...),
		Derivations:         derivations,
		Profiles:            profiles,
		Groups:              groups,
		Scenarios:           cloneScenarios(value.Scenarios),
	}
}

func cloneAtomicProjection(value AtomicProjection) AtomicProjection {
	return AtomicProjection{
		SourceID:            value.SourceID,
		SpecPackagePath:     value.SpecPackagePath,
		SourceNonClaimRefs:  cloneStrings(value.SourceNonClaimRefs),
		NonClaimDefinitions: append([]NonClaimDefinition(nil), value.NonClaimDefinitions...),
		Vocabulary:          append([]VocabularyTerm(nil), value.Vocabulary...),
		Requirements:        cloneAtomicRequirements(value.Requirements),
		Scenarios:           cloneScenarios(value.Scenarios),
	}
}

func cloneAtomicRequirements(values []AtomicRequirement) []AtomicRequirement {
	result := make([]AtomicRequirement, len(values))
	for index, value := range values {
		result[index] = AtomicRequirement{
			RequirementID:  value.RequirementID,
			Invariant:      value.Invariant,
			SharedPremises: cloneStrings(value.SharedPremises),
			OwnerID:        value.OwnerID,
			ClaimLevel:     value.ClaimLevel,
			RiskClass:      value.RiskClass,
			NonClaimRefs:   cloneStrings(value.NonClaimRefs),
			Lifecycle:      cloneLifecycle(value.Lifecycle),
			Deferral:       cloneDeferral(value.Deferral),
			UpdatePolicy:   value.UpdatePolicy,
		}
	}
	return result
}

func cloneLayoutProjection(value LayoutProjection) LayoutProjection {
	profiles := make([]Profile, len(value.Profiles))
	for index, profile := range value.Profiles {
		profiles[index] = Profile{ProfileID: profile.ProfileID, Fields: cloneMetadataFields(profile.Fields)}
	}
	groups := make([]Group, len(value.Groups))
	for index, group := range value.Groups {
		groups[index] = cloneGroup(group)
	}
	origins := make([]Origin, len(value.Origins))
	for index, origin := range value.Origins {
		origins[index] = Origin{
			RequirementID: origin.RequirementID,
			GroupID:       origin.GroupID,
			ProfileID:     origin.ProfileID,
			FieldOwners:   append([]FieldOwner(nil), origin.FieldOwners...),
		}
	}
	return LayoutProjection{SourceID: value.SourceID, Profiles: profiles, Groups: groups, Origins: origins}
}

func cloneReferenceProjection(value ReferenceProjection) ReferenceProjection {
	derivations := make([]Derivation, len(value.Derivations))
	for index, derivation := range value.Derivations {
		derivations[index] = cloneDerivation(derivation)
	}
	return ReferenceProjection{
		SourceID:    value.SourceID,
		Derivations: derivations,
		Edges:       append([]ReferenceEdge(nil), value.Edges...),
	}
}

func cloneGroup(value Group) Group {
	members := make([]Member, len(value.Members))
	for index, member := range value.Members {
		members[index] = Member{
			RequirementID:       member.RequirementID,
			StatementCompletion: member.StatementCompletion,
			Fields:              cloneMetadataFields(member.Fields),
		}
	}
	return Group{
		GroupID:        value.GroupID,
		ProfileID:      value.ProfileID,
		StatementStem:  value.StatementStem,
		SharedPremises: cloneStrings(value.SharedPremises),
		Members:        members,
	}
}

func cloneMetadataFields(value MetadataFields) MetadataFields {
	result := value
	if value.NonClaimRefs.Present {
		result.NonClaimRefs.Value = cloneStrings(value.NonClaimRefs.Value)
	}
	if value.Lifecycle.Present {
		result.Lifecycle.Value = cloneLifecycle(value.Lifecycle.Value)
	}
	if value.Deferral.Present {
		result.Deferral.Value = cloneDeferral(value.Deferral.Value)
	}
	return result
}

func cloneLifecycle(value Lifecycle) Lifecycle {
	return Lifecycle{
		State:                     value.State,
		ReplacementRequirementIDs: cloneStrings(value.ReplacementRequirementIDs),
		EvidenceRefs:              cloneStrings(value.EvidenceRefs),
	}
}

func cloneDeferral(value *Deferral) *Deferral {
	if value == nil {
		return nil
	}
	result := *value
	result.EvidenceRefs = cloneStrings(value.EvidenceRefs)
	return &result
}

func cloneScenarios(values []Scenario) []Scenario {
	result := make([]Scenario, len(values))
	for index, value := range values {
		examples := make([]Example, len(value.Examples))
		for exampleIndex, example := range value.Examples {
			items := make(map[string]ScenarioValue, len(example.Values))
			for key, item := range example.Values {
				items[key] = item
			}
			examples[exampleIndex] = Example{ExampleID: example.ExampleID, Values: items}
		}
		result[index] = Scenario{
			ScenarioID:            value.ScenarioID,
			RequirementIDs:        cloneStrings(value.RequirementIDs),
			Parameters:            cloneStrings(value.Parameters),
			Preconditions:         cloneStrings(value.Preconditions),
			ActionSequence:        cloneStrings(value.ActionSequence),
			ExpectedObservations:  cloneStrings(value.ExpectedObservations),
			ForbiddenObservations: cloneStrings(value.ForbiddenObservations),
			Examples:              examples,
			VocabularyRefs:        cloneStrings(value.VocabularyRefs),
			NonClaimRefs:          cloneStrings(value.NonClaimRefs),
		}
	}
	return result
}

func cloneDerivation(value Derivation) Derivation {
	return Derivation{
		DerivationID:   value.DerivationID,
		SourceKind:     value.SourceKind,
		SourceRef:      value.SourceRef,
		Selector:       value.Selector,
		RequirementIDs: cloneStrings(value.RequirementIDs),
		NonClaimRefs:   cloneStrings(value.NonClaimRefs),
	}
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}
