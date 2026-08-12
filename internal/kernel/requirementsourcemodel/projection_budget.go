package requirementsourcemodel

const materializationCopies = 2

type projectionCost struct {
	Items     uint64
	TextBytes uint64
}

type projectionBudget struct {
	cost         projectionCost
	itemOverflow bool
	textOverflow bool
}

func (budget *projectionBudget) records(count int) {
	if count < 0 || !addMultiplied(&budget.cost.Items, uint64(count), materializationCopies) {
		budget.itemOverflow = true
	}
}

func (budget *projectionBudget) text(values ...string) {
	for _, value := range values {
		budget.records(1)
		budget.addTextBytes(value)
	}
}

func (budget *projectionBudget) composedText(values ...string) {
	budget.records(1)
	for _, value := range values {
		budget.addTextBytes(value)
	}
}

func (budget *projectionBudget) addTextBytes(value string) {
	if !addMultiplied(&budget.cost.TextBytes, uint64(len(value)), materializationCopies) {
		budget.textOverflow = true
	}
}

func (budget *projectionBudget) texts(values []string) {
	for _, value := range values {
		budget.text(value)
	}
}

func addMultiplied(total *uint64, value uint64, multiplier uint64) bool {
	maximum := ^uint64(0)
	if multiplier != 0 && value > maximum/multiplier {
		return false
	}
	amount := value * multiplier
	if amount > maximum-*total {
		return false
	}
	*total += amount
	return true
}

func preflightExpandedProjectionBudget(draft Draft, limits Limits) error {
	cost, itemOverflow, textOverflow := estimateExpandedProjectionCost(draft)
	if itemOverflow || cost.Items > uint64(limits.MaxExpandedItems) {
		return invalid("expanded_item_budget_exceeded", "draft")
	}
	if textOverflow || cost.TextBytes > uint64(limits.MaxExpandedTextBytes) {
		return invalid("expanded_text_budget_exceeded", "draft")
	}
	return nil
}

func estimateExpandedProjectionCost(draft Draft) (projectionCost, bool, bool) {
	budget := &projectionBudget{}
	profiles := make(map[string]MetadataFields, len(draft.Profiles))
	for _, profile := range draft.Profiles {
		profiles[profile.ProfileID] = profile.Fields
	}

	budget.records(3)
	budget.text(draft.SourceID, draft.SpecPackagePath)
	budget.texts(draft.SourceNonClaimRefs)
	for _, definition := range draft.NonClaimDefinitions {
		budget.records(1)
		budget.text(definition.NonClaimID, definition.Statement)
	}
	for _, term := range draft.Vocabulary {
		budget.records(1)
		budget.text(term.TermID, string(term.Kind), term.Label, term.Definition)
	}
	for _, group := range draft.Groups {
		profile := profiles[group.ProfileID]
		for _, member := range group.Members {
			budget.records(1)
			budget.text(member.RequirementID)
			separator := ""
			if group.StatementStem != "" {
				separator = " "
			}
			budget.composedText(group.StatementStem, separator, member.StatementCompletion)
			budget.texts(group.SharedPremises)
			budget.atomicMetadata(profile, member.Fields)
		}
	}
	for _, scenario := range draft.Scenarios {
		budget.scenario(scenario)
	}

	budget.text(draft.SourceID)
	for _, profile := range draft.Profiles {
		budget.records(1)
		budget.text(profile.ProfileID)
		budget.layoutMetadata(profile.Fields)
	}
	for _, group := range draft.Groups {
		budget.records(1)
		budget.text(group.GroupID, group.ProfileID, group.StatementStem)
		budget.texts(group.SharedPremises)
		for _, member := range group.Members {
			budget.records(1)
			budget.text(member.RequirementID, member.StatementCompletion)
			budget.layoutMetadata(member.Fields)
		}
	}
	for _, group := range draft.Groups {
		profile := profiles[group.ProfileID]
		profilePresence := metadataPresence(profile)
		for _, member := range group.Members {
			budget.records(1)
			budget.text(member.RequirementID, group.GroupID, group.ProfileID)
			for _, fieldID := range metadataFieldIDs {
				budget.records(1)
				if profilePresence[fieldID] {
					budget.text(string(fieldID), string(MetadataOwnerProfile), group.ProfileID)
				} else {
					budget.text(string(fieldID), string(MetadataOwnerMember), member.RequirementID)
				}
			}
		}
	}

	budget.text(draft.SourceID)
	for _, derivation := range draft.Derivations {
		budget.derivation(derivation)
	}
	for _, nonClaimID := range draft.SourceNonClaimRefs {
		budget.edge(ReferenceSourceNonClaim, EntitySource, draft.SourceID, EntityNonClaim, nonClaimID)
	}
	for _, group := range draft.Groups {
		if group.ProfileID != "" {
			budget.edge(ReferenceGroupProfile, EntityGroup, group.GroupID, EntityProfile, group.ProfileID)
		}
		profile := profiles[group.ProfileID]
		for _, member := range group.Members {
			budget.edge(ReferenceGroupMember, EntityGroup, group.GroupID, EntityRequirement, member.RequirementID)
			budget.metadataEdges(member.RequirementID, profile)
			budget.metadataEdges(member.RequirementID, member.Fields)
		}
	}
	for _, scenario := range draft.Scenarios {
		for _, requirementID := range scenario.RequirementIDs {
			budget.edge(ReferenceScenarioRequirement, EntityScenario, scenario.ScenarioID, EntityRequirement, requirementID)
		}
		for _, termID := range scenario.VocabularyRefs {
			budget.edge(ReferenceScenarioVocabulary, EntityScenario, scenario.ScenarioID, EntityTerm, termID)
		}
		for _, nonClaimID := range scenario.NonClaimRefs {
			budget.edge(ReferenceScenarioNonClaim, EntityScenario, scenario.ScenarioID, EntityNonClaim, nonClaimID)
		}
	}
	for _, derivation := range draft.Derivations {
		for _, requirementID := range derivation.RequirementIDs {
			budget.edge(ReferenceDerivationRequirement, EntityDerivation, derivation.DerivationID, EntityRequirement, requirementID)
		}
		for _, nonClaimID := range derivation.NonClaimRefs {
			budget.edge(ReferenceDerivationNonClaim, EntityDerivation, derivation.DerivationID, EntityNonClaim, nonClaimID)
		}
	}

	return budget.cost, budget.itemOverflow, budget.textOverflow
}

func (budget *projectionBudget) layoutMetadata(fields MetadataFields) {
	budget.records(1 + len(metadataFieldIDs))
	if fields.OwnerID.Present {
		budget.text(fields.OwnerID.Value)
	}
	if fields.ClaimLevel.Present {
		budget.text(string(fields.ClaimLevel.Value))
	}
	if fields.RiskClass.Present {
		budget.text(string(fields.RiskClass.Value))
	}
	if fields.NonClaimRefs.Present {
		budget.texts(fields.NonClaimRefs.Value)
	}
	if fields.Lifecycle.Present {
		budget.records(1)
		budget.text(string(fields.Lifecycle.Value.State))
		budget.texts(fields.Lifecycle.Value.ReplacementRequirementIDs)
		budget.texts(fields.Lifecycle.Value.EvidenceRefs)
	}
	if fields.Deferral.Present {
		if fields.Deferral.Value != nil {
			budget.records(1)
			value := fields.Deferral.Value
			budget.text(value.OwnerID, value.RiskAcceptedBy, value.ReviewCondition, value.ExpiryRef, value.MergePolicy)
			budget.texts(value.EvidenceRefs)
		}
	}
	if fields.UpdatePolicy.Present {
		budget.records(1)
		budget.text(fields.UpdatePolicy.Value.ReviewOwnerID)
	}
}

func (budget *projectionBudget) atomicMetadata(profile MetadataFields, member MetadataFields) {
	budget.records(2) // Lifecycle and UpdatePolicy are value fields.
	budget.text(
		selectedField(profile.OwnerID, member.OwnerID),
		string(selectedField(profile.ClaimLevel, member.ClaimLevel)),
		string(selectedField(profile.RiskClass, member.RiskClass)),
	)
	budget.texts(selectedField(profile.NonClaimRefs, member.NonClaimRefs))
	lifecycle := selectedField(profile.Lifecycle, member.Lifecycle)
	budget.text(string(lifecycle.State))
	budget.texts(lifecycle.ReplacementRequirementIDs)
	budget.texts(lifecycle.EvidenceRefs)
	if deferral := selectedField(profile.Deferral, member.Deferral); deferral != nil {
		budget.records(1)
		budget.text(deferral.OwnerID, deferral.RiskAcceptedBy, deferral.ReviewCondition, deferral.ExpiryRef, deferral.MergePolicy)
		budget.texts(deferral.EvidenceRefs)
	}
	budget.text(selectedField(profile.UpdatePolicy, member.UpdatePolicy).ReviewOwnerID)
}

func selectedField[T any](profile Field[T], member Field[T]) T {
	if profile.Present {
		return profile.Value
	}
	return member.Value
}

func (budget *projectionBudget) scenario(value Scenario) {
	budget.records(1)
	budget.text(value.ScenarioID)
	budget.texts(value.RequirementIDs)
	budget.texts(value.Parameters)
	budget.texts(value.Preconditions)
	budget.texts(value.ActionSequence)
	budget.texts(value.ExpectedObservations)
	budget.texts(value.ForbiddenObservations)
	budget.texts(value.VocabularyRefs)
	budget.texts(value.NonClaimRefs)
	for _, example := range value.Examples {
		budget.records(2) // Example and its Values map.
		budget.text(example.ExampleID)
		for key, scalar := range example.Values {
			budget.text(key, string(scalar))
		}
	}
}

func (budget *projectionBudget) derivation(value Derivation) {
	budget.records(3) // Derivation, GitBlobRef, and ByteRange.
	budget.text(value.DerivationID, string(value.SourceKind), string(value.SourceRef.ObjectFormat), value.SourceRef.CommitOID, value.SourceRef.Path, value.SourceRef.SHA256)
	budget.texts(value.RequirementIDs)
	budget.texts(value.NonClaimRefs)
}

func (budget *projectionBudget) metadataEdges(requirementID string, fields MetadataFields) {
	if fields.NonClaimRefs.Present {
		for _, nonClaimID := range fields.NonClaimRefs.Value {
			budget.edge(ReferenceRequirementNonClaim, EntityRequirement, requirementID, EntityNonClaim, nonClaimID)
		}
	}
	if fields.Lifecycle.Present {
		for _, replacementID := range fields.Lifecycle.Value.ReplacementRequirementIDs {
			budget.edge(ReferenceLifecycleReplacement, EntityRequirement, requirementID, EntityRequirement, replacementID)
		}
	}
}

func (budget *projectionBudget) edge(kind ReferenceKind, fromKind EntityKind, fromID string, toKind EntityKind, toID string) {
	budget.records(3) // ReferenceEdge and its two typed endpoints.
	budget.text(string(kind), string(fromKind), fromID, string(toKind), toID)
}
