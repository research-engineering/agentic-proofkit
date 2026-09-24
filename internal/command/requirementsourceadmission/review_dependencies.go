package requirementsourceadmission

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type reviewReference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type scenarioReview struct {
	Body           requirementsourcemodel.Scenario `json:"body"`
	NamedNonClaims []reviewReference               `json:"namedNonClaims"`
	Vocabulary     []reviewReference               `json:"vocabulary"`
}

type derivationReview struct {
	Body           requirementsourcemodel.Derivation `json:"body"`
	NamedNonClaims []reviewReference                 `json:"namedNonClaims"`
}

type requirementReview struct {
	SourceID       string            `json:"sourceId"`
	RequirementID  string            `json:"requirementId"`
	SourceBoundary string            `json:"sourceBoundary"`
	NamedNonClaims []reviewReference `json:"namedNonClaims"`
	Scenarios      []reviewReference `json:"scenarios"`
	Derivations    []reviewReference `json:"derivations"`
}

// reviewDependencyDigests binds source-scoped meaning reachable from each
// requirement without treating a digest as execution or freshness evidence.
func reviewDependencyDigests(model requirementsourcemodel.Model) (map[string]string, error) {
	atomic := model.Atomic()
	definitions := make(map[string]string, len(atomic.NonClaimDefinitions))
	for _, definition := range atomic.NonClaimDefinitions {
		value, err := reviewDigest(definition)
		if err != nil {
			return nil, err
		}
		definitions[definition.NonClaimID] = value
	}
	vocabulary := make(map[string]string, len(atomic.Vocabulary))
	for _, term := range atomic.Vocabulary {
		value, err := reviewDigest(term)
		if err != nil {
			return nil, err
		}
		vocabulary[term.TermID] = value
	}
	sourceBoundary, err := reviewDigest(model.ResolvedSourceNonClaims())
	if err != nil {
		return nil, err
	}
	scenarios := make(map[string][]reviewReference, len(atomic.Requirements))
	for _, scenario := range atomic.Scenarios {
		named, err := reviewReferences(scenario.NonClaimRefs, definitions)
		if err != nil {
			return nil, err
		}
		terms, err := reviewReferences(scenario.VocabularyRefs, vocabulary)
		if err != nil {
			return nil, err
		}
		value, err := reviewDigest(scenarioReview{Body: scenario, NamedNonClaims: named, Vocabulary: terms})
		if err != nil {
			return nil, err
		}
		for _, requirementID := range scenario.RequirementIDs {
			scenarios[requirementID] = append(scenarios[requirementID], reviewReference{ID: scenario.ScenarioID, Digest: value})
		}
	}
	derivations := make(map[string][]reviewReference, len(atomic.Requirements))
	for _, derivation := range model.References().Derivations {
		named, err := reviewReferences(derivation.NonClaimRefs, definitions)
		if err != nil {
			return nil, err
		}
		value, err := reviewDigest(derivationReview{Body: derivation, NamedNonClaims: named})
		if err != nil {
			return nil, err
		}
		for _, requirementID := range derivation.RequirementIDs {
			derivations[requirementID] = append(derivations[requirementID], reviewReference{ID: derivation.DerivationID, Digest: value})
		}
	}
	result := make(map[string]string, len(atomic.Requirements))
	for _, requirement := range atomic.Requirements {
		id := requirement.RequirementID
		named, err := reviewReferences(requirement.NonClaimRefs, definitions)
		if err != nil {
			return nil, err
		}
		value, err := reviewDigest(requirementReview{
			SourceID: atomic.SourceID, RequirementID: id, SourceBoundary: sourceBoundary,
			NamedNonClaims: named, Scenarios: sortedReviewReferences(scenarios[id]),
			Derivations: sortedReviewReferences(derivations[id]),
		})
		if err != nil {
			return nil, err
		}
		result[id] = value
	}
	return result, nil
}

func reviewReferences(ids []string, digests map[string]string) ([]reviewReference, error) {
	result := make([]reviewReference, 0, len(ids))
	for _, id := range ids {
		value, ok := digests[id]
		if !ok {
			return nil, fmt.Errorf("admitted source review dependency does not resolve")
		}
		result = append(result, reviewReference{ID: id, Digest: value})
	}
	return sortedReviewReferences(result), nil
}

func sortedReviewReferences(values []reviewReference) []reviewReference {
	result := append([]reviewReference{}, values...)
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func reviewDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode admitted source review dependency: %w", err)
	}
	return digest.SHA256BytesRef(encoded), nil
}
