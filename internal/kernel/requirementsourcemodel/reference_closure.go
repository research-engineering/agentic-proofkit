package requirementsourcemodel

import "sort"

func endpoint(kind EntityKind, id string) ReferenceEndpoint {
	return ReferenceEndpoint{Kind: kind, ID: id}
}

func buildReferenceEdges(sourceID string, sourceNonClaimRefs []string, groups []Group, requirements []AtomicRequirement, scenarios []Scenario, derivations []Derivation) []ReferenceEdge {
	edges := make([]ReferenceEdge, 0)
	for _, nonClaimID := range sourceNonClaimRefs {
		edges = append(edges, ReferenceEdge{Kind: ReferenceSourceNonClaim, From: endpoint(EntitySource, sourceID), To: endpoint(EntityNonClaim, nonClaimID)})
	}
	for _, group := range groups {
		if group.ProfileID != "" {
			edges = append(edges, ReferenceEdge{Kind: ReferenceGroupProfile, From: endpoint(EntityGroup, group.GroupID), To: endpoint(EntityProfile, group.ProfileID)})
		}
		for _, member := range group.Members {
			edges = append(edges, ReferenceEdge{Kind: ReferenceGroupMember, From: endpoint(EntityGroup, group.GroupID), To: endpoint(EntityRequirement, member.RequirementID)})
		}
	}
	for _, requirement := range requirements {
		for _, nonClaimID := range requirement.NonClaimRefs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceRequirementNonClaim, From: endpoint(EntityRequirement, requirement.RequirementID), To: endpoint(EntityNonClaim, nonClaimID)})
		}
		for _, replacementID := range requirement.Lifecycle.ReplacementRequirementIDs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceLifecycleReplacement, From: endpoint(EntityRequirement, requirement.RequirementID), To: endpoint(EntityRequirement, replacementID)})
		}
	}
	for _, scenario := range scenarios {
		for _, requirementID := range scenario.RequirementIDs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceScenarioRequirement, From: endpoint(EntityScenario, scenario.ScenarioID), To: endpoint(EntityRequirement, requirementID)})
		}
		for _, termID := range scenario.VocabularyRefs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceScenarioVocabulary, From: endpoint(EntityScenario, scenario.ScenarioID), To: endpoint(EntityTerm, termID)})
		}
		for _, nonClaimID := range scenario.NonClaimRefs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceScenarioNonClaim, From: endpoint(EntityScenario, scenario.ScenarioID), To: endpoint(EntityNonClaim, nonClaimID)})
		}
	}
	for _, derivation := range derivations {
		for _, requirementID := range derivation.RequirementIDs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceDerivationRequirement, From: endpoint(EntityDerivation, derivation.DerivationID), To: endpoint(EntityRequirement, requirementID)})
		}
		for _, nonClaimID := range derivation.NonClaimRefs {
			edges = append(edges, ReferenceEdge{Kind: ReferenceDerivationNonClaim, From: endpoint(EntityDerivation, derivation.DerivationID), To: endpoint(EntityNonClaim, nonClaimID)})
		}
	}
	sort.Slice(edges, func(left int, right int) bool {
		if edges[left].Kind != edges[right].Kind {
			return edges[left].Kind < edges[right].Kind
		}
		if edges[left].From.Kind != edges[right].From.Kind {
			return edges[left].From.Kind < edges[right].From.Kind
		}
		if edges[left].From.ID != edges[right].From.ID {
			return edges[left].From.ID < edges[right].From.ID
		}
		if edges[left].To.Kind != edges[right].To.Kind {
			return edges[left].To.Kind < edges[right].To.Kind
		}
		return edges[left].To.ID < edges[right].To.ID
	})
	return edges
}

func validateReferenceClosure(definitions map[string]struct{}, vocabulary map[string]struct{}, edges []ReferenceEdge) error {
	usedDefinitions := map[string]struct{}{}
	usedVocabulary := map[string]struct{}{}
	seenEdges := map[ReferenceEdge]struct{}{}
	for _, edge := range edges {
		if _, exists := seenEdges[edge]; exists {
			return invalid("duplicate_reference_edge", "references")
		}
		seenEdges[edge] = struct{}{}
		switch edge.Kind {
		case ReferenceSourceNonClaim, ReferenceRequirementNonClaim, ReferenceScenarioNonClaim, ReferenceDerivationNonClaim:
			if edge.To.Kind != EntityNonClaim {
				return invalid("invalid_reference_role", "references")
			}
			if _, exists := definitions[edge.To.ID]; !exists {
				return invalid("dangling_nonclaim_ref", "references")
			}
			usedDefinitions[edge.To.ID] = struct{}{}
		case ReferenceScenarioVocabulary:
			if edge.To.Kind != EntityTerm {
				return invalid("invalid_reference_role", "references")
			}
			if _, exists := vocabulary[edge.To.ID]; !exists {
				return invalid("dangling_vocabulary_ref", "references")
			}
			usedVocabulary[edge.To.ID] = struct{}{}
		}
	}
	for _, definitionID := range sortedSetKeys(definitions) {
		if _, exists := usedDefinitions[definitionID]; !exists {
			return invalid("unreferenced_definition", "nonClaimDefinitions."+definitionID)
		}
	}
	for _, termID := range sortedSetKeys(vocabulary) {
		if _, exists := usedVocabulary[termID]; !exists {
			return invalid("unreferenced_vocabulary", "vocabulary."+termID)
		}
	}
	return nil
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
