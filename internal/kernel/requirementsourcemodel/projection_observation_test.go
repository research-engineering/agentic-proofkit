package requirementsourcemodel

import "sort"

type metadataObservation struct {
	RequirementID string
	OwnerKind     MetadataOwnerKind
	OwnerID       string
	Present       bool
	Value         any
}

func observeManifestField(model Model, fieldID string, projection string) (any, bool) {
	atomic := model.Atomic()
	layout := model.Layout()
	references := model.References()
	switch fieldID {
	case "source.id":
		switch projection {
		case "atomic":
			return atomic.SourceID, true
		case "layout":
			return layout.SourceID, true
		case "references":
			return references.SourceID, true
		}
	case "source.specPackagePath":
		return atomic.SpecPackagePath, projection == "atomic"
	case "source.nonClaimRefs":
		switch projection {
		case "atomic":
			return atomic.SourceNonClaimRefs, true
		case "references":
			return observeEdges(references, ReferenceSourceNonClaim), true
		}
	case "nonClaim.id":
		switch projection {
		case "atomic":
			return mapDefinitions(atomic, func(value NonClaimDefinition) any { return value.NonClaimID }), true
		case "references":
			return observeEdgesTo(references, EntityNonClaim), true
		}
	case "nonClaim.statement":
		return mapDefinitions(atomic, func(value NonClaimDefinition) any { return value.Statement }), projection == "atomic"
	case "vocabulary.id":
		switch projection {
		case "atomic":
			return mapVocabulary(atomic, func(value VocabularyTerm) any { return value.TermID }), true
		case "references":
			return observeEdges(references, ReferenceScenarioVocabulary), true
		}
	case "vocabulary.kind":
		return mapVocabulary(atomic, func(value VocabularyTerm) any { return value.Kind }), projection == "atomic"
	case "vocabulary.label":
		return mapVocabulary(atomic, func(value VocabularyTerm) any { return value.Label }), projection == "atomic"
	case "vocabulary.definition":
		return mapVocabulary(atomic, func(value VocabularyTerm) any { return value.Definition }), projection == "atomic"
	case "derivation.id":
		return mapDerivations(references, func(value Derivation) any { return value.DerivationID }), projection == "references"
	case "derivation.sourceKind":
		return mapDerivations(references, func(value Derivation) any { return value.SourceKind }), projection == "references"
	case "derivation.sourceRef.objectFormat":
		return mapDerivations(references, func(value Derivation) any { return value.SourceRef.ObjectFormat }), projection == "references"
	case "derivation.sourceRef.commitOid":
		return mapDerivations(references, func(value Derivation) any { return value.SourceRef.CommitOID }), projection == "references"
	case "derivation.sourceRef.path":
		return mapDerivations(references, func(value Derivation) any { return value.SourceRef.Path }), projection == "references"
	case "derivation.sourceRef.sha256":
		return mapDerivations(references, func(value Derivation) any { return value.SourceRef.SHA256 }), projection == "references"
	case "derivation.selector.start":
		return mapDerivations(references, func(value Derivation) any { return value.Selector.Start }), projection == "references"
	case "derivation.selector.end":
		return mapDerivations(references, func(value Derivation) any { return value.Selector.End }), projection == "references"
	case "derivation.requirementIds":
		return mapDerivations(references, func(value Derivation) any { return value.RequirementIDs }), projection == "references"
	case "derivation.nonClaimRefs":
		return mapDerivations(references, func(value Derivation) any { return value.NonClaimRefs }), projection == "references"
	case "profile.id":
		switch projection {
		case "layout":
			result := make([]string, len(layout.Profiles))
			for index, profile := range layout.Profiles {
				result[index] = profile.ProfileID
			}
			return result, true
		case "references":
			return observeEdges(references, ReferenceGroupProfile), true
		}
	case "metadata.ownerId", "metadata.claimLevel", "metadata.riskClass", "metadata.nonClaimRefs",
		"metadata.lifecycle.state", "metadata.lifecycle.replacementRequirementIds", "metadata.lifecycle.evidenceRefs",
		"metadata.deferral.presence", "metadata.deferral.ownerId", "metadata.deferral.riskAcceptedBy",
		"metadata.deferral.reviewCondition", "metadata.deferral.expiryRef", "metadata.deferral.mergePolicy",
		"metadata.deferral.evidenceRefs", "metadata.updatePolicy.reviewOwnerId",
		"metadata.updatePolicy.requiresImpactDeclaration", "metadata.updatePolicy.requiresProofBindingReview":
		switch projection {
		case "atomic":
			return observeAtomicMetadata(atomic, fieldID), true
		case "layout":
			return observeLayoutMetadata(layout, fieldID), true
		case "references":
			switch fieldID {
			case "metadata.nonClaimRefs":
				return observeEdges(references, ReferenceRequirementNonClaim), true
			case "metadata.lifecycle.replacementRequirementIds":
				return observeEdges(references, ReferenceLifecycleReplacement), true
			}
		}
	case "group.id":
		switch projection {
		case "layout":
			return mapGroups(layout, func(value Group) any { return value.GroupID }), true
		case "references":
			return observeEdgesFrom(references, EntityGroup), true
		}
	case "group.memberRefs":
		switch projection {
		case "layout":
			return observeLayoutGroupMembers(layout), true
		case "references":
			return observeEdges(references, ReferenceGroupMember), true
		}
	case "group.profileRef":
		switch projection {
		case "layout":
			return mapGroups(layout, func(value Group) any { return value.ProfileID }), true
		case "references":
			return observeEdges(references, ReferenceGroupProfile), true
		}
	case "group.statementStem":
		switch projection {
		case "atomic":
			return mapRequirements(atomic, func(value AtomicRequirement) any { return value.Invariant }), true
		case "layout":
			return mapGroups(layout, func(value Group) any { return value.StatementStem }), true
		}
	case "group.sharedPremises":
		switch projection {
		case "atomic":
			return mapRequirements(atomic, func(value AtomicRequirement) any { return value.SharedPremises }), true
		case "layout":
			return mapGroups(layout, func(value Group) any { return value.SharedPremises }), true
		}
	case "member.requirementId":
		switch projection {
		case "atomic":
			return mapRequirements(atomic, func(value AtomicRequirement) any { return value.RequirementID }), true
		case "layout":
			return mapMembers(layout, func(value Member) any { return value.RequirementID }), true
		case "references":
			return observeEdges(references, ReferenceGroupMember), true
		}
	case "member.statementCompletion":
		switch projection {
		case "atomic":
			return mapRequirements(atomic, func(value AtomicRequirement) any { return value.Invariant }), true
		case "layout":
			return mapMembers(layout, func(value Member) any { return value.StatementCompletion }), true
		}
	case "scenario.id":
		switch projection {
		case "atomic":
			return mapScenarios(atomic, func(value Scenario) any { return value.ScenarioID }), true
		case "references":
			return observeEdgesFrom(references, EntityScenario), true
		}
	case "scenario.requirementIds":
		switch projection {
		case "atomic":
			return mapScenarios(atomic, func(value Scenario) any { return value.RequirementIDs }), true
		case "references":
			return observeEdges(references, ReferenceScenarioRequirement), true
		}
	case "scenario.parameters":
		return mapScenarios(atomic, func(value Scenario) any { return value.Parameters }), projection == "atomic"
	case "scenario.preconditions":
		return mapScenarios(atomic, func(value Scenario) any { return value.Preconditions }), projection == "atomic"
	case "scenario.actionSequence":
		return mapScenarios(atomic, func(value Scenario) any { return value.ActionSequence }), projection == "atomic"
	case "scenario.expectedObservations":
		return mapScenarios(atomic, func(value Scenario) any { return value.ExpectedObservations }), projection == "atomic"
	case "scenario.forbiddenObservations":
		return mapScenarios(atomic, func(value Scenario) any { return value.ForbiddenObservations }), projection == "atomic"
	case "scenario.example.id":
		return mapExamples(atomic, func(value Example) any { return value.ExampleID }), projection == "atomic"
	case "scenario.example.values":
		return mapExamples(atomic, func(value Example) any { return value.Values }), projection == "atomic"
	case "scenario.vocabularyRefs":
		switch projection {
		case "atomic":
			return mapScenarios(atomic, func(value Scenario) any { return value.VocabularyRefs }), true
		case "references":
			return observeEdges(references, ReferenceScenarioVocabulary), true
		}
	case "scenario.nonClaimRefs":
		switch projection {
		case "atomic":
			return mapScenarios(atomic, func(value Scenario) any { return value.NonClaimRefs }), true
		case "references":
			return observeEdges(references, ReferenceScenarioNonClaim), true
		}
	}
	return nil, false
}

func mapDefinitions(value AtomicProjection, project func(NonClaimDefinition) any) []any {
	result := make([]any, len(value.NonClaimDefinitions))
	for index, item := range value.NonClaimDefinitions {
		result[index] = project(item)
	}
	return result
}

func mapVocabulary(value AtomicProjection, project func(VocabularyTerm) any) []any {
	result := make([]any, len(value.Vocabulary))
	for index, item := range value.Vocabulary {
		result[index] = project(item)
	}
	return result
}

func mapDerivations(value ReferenceProjection, project func(Derivation) any) []any {
	result := make([]any, len(value.Derivations))
	for index, item := range value.Derivations {
		result[index] = project(item)
	}
	return result
}

func mapRequirements(value AtomicProjection, project func(AtomicRequirement) any) []any {
	result := make([]any, len(value.Requirements))
	for index, item := range value.Requirements {
		result[index] = project(item)
	}
	return result
}

func mapGroups(value LayoutProjection, project func(Group) any) []any {
	result := make([]any, len(value.Groups))
	for index, item := range value.Groups {
		result[index] = project(item)
	}
	return result
}

func mapMembers(value LayoutProjection, project func(Member) any) []any {
	result := []any{}
	for _, group := range value.Groups {
		for _, member := range group.Members {
			result = append(result, project(member))
		}
	}
	return result
}

func observeLayoutGroupMembers(value LayoutProjection) []string {
	result := []string{}
	for _, group := range value.Groups {
		for _, member := range group.Members {
			result = append(result, group.GroupID+"\x00"+member.RequirementID)
		}
	}
	sort.Strings(result)
	return result
}

func mapScenarios(value AtomicProjection, project func(Scenario) any) []any {
	result := make([]any, len(value.Scenarios))
	for index, item := range value.Scenarios {
		result[index] = project(item)
	}
	return result
}

func mapExamples(value AtomicProjection, project func(Example) any) []any {
	result := []any{}
	for _, scenario := range value.Scenarios {
		for _, example := range scenario.Examples {
			result = append(result, project(example))
		}
	}
	return result
}

func observeEdges(value ReferenceProjection, kind ReferenceKind) []ReferenceEdge {
	result := []ReferenceEdge{}
	for _, edge := range value.Edges {
		if edge.Kind == kind {
			result = append(result, edge)
		}
	}
	return result
}

func observeEdgesFrom(value ReferenceProjection, kind EntityKind) []ReferenceEdge {
	result := []ReferenceEdge{}
	for _, edge := range value.Edges {
		if edge.From.Kind == kind {
			result = append(result, edge)
		}
	}
	return result
}

func observeEdgesTo(value ReferenceProjection, kind EntityKind) []ReferenceEdge {
	result := []ReferenceEdge{}
	for _, edge := range value.Edges {
		if edge.To.Kind == kind {
			result = append(result, edge)
		}
	}
	return result
}

func observeAtomicMetadata(value AtomicProjection, fieldID string) []any {
	return mapRequirements(value, func(requirement AtomicRequirement) any {
		switch fieldID {
		case "metadata.ownerId":
			return requirement.OwnerID
		case "metadata.claimLevel":
			return requirement.ClaimLevel
		case "metadata.riskClass":
			return requirement.RiskClass
		case "metadata.nonClaimRefs":
			return requirement.NonClaimRefs
		case "metadata.lifecycle.state":
			return requirement.Lifecycle.State
		case "metadata.lifecycle.replacementRequirementIds":
			return requirement.Lifecycle.ReplacementRequirementIDs
		case "metadata.lifecycle.evidenceRefs":
			return requirement.Lifecycle.EvidenceRefs
		case "metadata.deferral.presence":
			return requirement.Deferral != nil
		case "metadata.deferral.ownerId":
			return deferralField(requirement.Deferral, func(value *Deferral) any { return value.OwnerID })
		case "metadata.deferral.riskAcceptedBy":
			return deferralField(requirement.Deferral, func(value *Deferral) any { return value.RiskAcceptedBy })
		case "metadata.deferral.reviewCondition":
			return deferralField(requirement.Deferral, func(value *Deferral) any { return value.ReviewCondition })
		case "metadata.deferral.expiryRef":
			return deferralField(requirement.Deferral, func(value *Deferral) any { return value.ExpiryRef })
		case "metadata.deferral.mergePolicy":
			return deferralField(requirement.Deferral, func(value *Deferral) any { return value.MergePolicy })
		case "metadata.deferral.evidenceRefs":
			return deferralField(requirement.Deferral, func(value *Deferral) any { return value.EvidenceRefs })
		case "metadata.updatePolicy.reviewOwnerId":
			return requirement.UpdatePolicy.ReviewOwnerID
		case "metadata.updatePolicy.requiresImpactDeclaration":
			return requirement.UpdatePolicy.RequiresImpactDeclaration
		case "metadata.updatePolicy.requiresProofBindingReview":
			return requirement.UpdatePolicy.RequiresProofBindingReview
		}
		return nil
	})
}

func observeLayoutMetadata(value LayoutProjection, fieldID string) []metadataObservation {
	profiles := map[string]MetadataFields{}
	for _, profile := range value.Profiles {
		profiles[profile.ProfileID] = profile.Fields
	}
	result := []metadataObservation{}
	for _, group := range value.Groups {
		for _, member := range group.Members {
			profileFields := profiles[group.ProfileID]
			ownerKind := MetadataOwnerMember
			ownerID := member.RequirementID
			fields := member.Fields
			if metadataFieldPresent(profileFields, fieldID) {
				ownerKind = MetadataOwnerProfile
				ownerID = group.ProfileID
				fields = profileFields
			}
			present, fieldValue := metadataFieldValue(fields, fieldID)
			result = append(result, metadataObservation{RequirementID: member.RequirementID, OwnerKind: ownerKind, OwnerID: ownerID, Present: present, Value: fieldValue})
		}
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].RequirementID < result[right].RequirementID })
	return result
}

func metadataFieldPresent(value MetadataFields, fieldID string) bool {
	switch {
	case fieldID == "metadata.ownerId":
		return value.OwnerID.Present
	case fieldID == "metadata.claimLevel":
		return value.ClaimLevel.Present
	case fieldID == "metadata.riskClass":
		return value.RiskClass.Present
	case fieldID == "metadata.nonClaimRefs":
		return value.NonClaimRefs.Present
	case fieldID == "metadata.lifecycle.state" || fieldID == "metadata.lifecycle.replacementRequirementIds" || fieldID == "metadata.lifecycle.evidenceRefs":
		return value.Lifecycle.Present
	case fieldID == "metadata.deferral.presence" || stringsHasPrefix(fieldID, "metadata.deferral."):
		return value.Deferral.Present
	case stringsHasPrefix(fieldID, "metadata.updatePolicy."):
		return value.UpdatePolicy.Present
	}
	return false
}

func metadataFieldValue(value MetadataFields, fieldID string) (bool, any) {
	switch fieldID {
	case "metadata.ownerId":
		return value.OwnerID.Present, value.OwnerID.Value
	case "metadata.claimLevel":
		return value.ClaimLevel.Present, value.ClaimLevel.Value
	case "metadata.riskClass":
		return value.RiskClass.Present, value.RiskClass.Value
	case "metadata.nonClaimRefs":
		return value.NonClaimRefs.Present, value.NonClaimRefs.Value
	case "metadata.lifecycle.state":
		return value.Lifecycle.Present, value.Lifecycle.Value.State
	case "metadata.lifecycle.replacementRequirementIds":
		return value.Lifecycle.Present, value.Lifecycle.Value.ReplacementRequirementIDs
	case "metadata.lifecycle.evidenceRefs":
		return value.Lifecycle.Present, value.Lifecycle.Value.EvidenceRefs
	case "metadata.deferral.presence":
		return value.Deferral.Present, value.Deferral.Value != nil
	case "metadata.deferral.ownerId":
		return value.Deferral.Present, deferralField(value.Deferral.Value, func(item *Deferral) any { return item.OwnerID })
	case "metadata.deferral.riskAcceptedBy":
		return value.Deferral.Present, deferralField(value.Deferral.Value, func(item *Deferral) any { return item.RiskAcceptedBy })
	case "metadata.deferral.reviewCondition":
		return value.Deferral.Present, deferralField(value.Deferral.Value, func(item *Deferral) any { return item.ReviewCondition })
	case "metadata.deferral.expiryRef":
		return value.Deferral.Present, deferralField(value.Deferral.Value, func(item *Deferral) any { return item.ExpiryRef })
	case "metadata.deferral.mergePolicy":
		return value.Deferral.Present, deferralField(value.Deferral.Value, func(item *Deferral) any { return item.MergePolicy })
	case "metadata.deferral.evidenceRefs":
		return value.Deferral.Present, deferralField(value.Deferral.Value, func(item *Deferral) any { return item.EvidenceRefs })
	case "metadata.updatePolicy.reviewOwnerId":
		return value.UpdatePolicy.Present, value.UpdatePolicy.Value.ReviewOwnerID
	case "metadata.updatePolicy.requiresImpactDeclaration":
		return value.UpdatePolicy.Present, value.UpdatePolicy.Value.RequiresImpactDeclaration
	case "metadata.updatePolicy.requiresProofBindingReview":
		return value.UpdatePolicy.Present, value.UpdatePolicy.Value.RequiresProofBindingReview
	}
	return false, nil
}

func deferralField(value *Deferral, project func(*Deferral) any) any {
	if value == nil {
		return nil
	}
	return project(value)
}

func stringsHasPrefix(value string, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
