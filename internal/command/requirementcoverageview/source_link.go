package requirementcoverageview

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

// AdmitSourceLink binds an admitted coverage projection to the exact source
// revision consumed by a parent, without promoting coverage into proof truth.
func AdmitSourceLink(output map[string]any, source requirementsourceadmission.Source) error {
	if output["sourceId"] != source.SourceID() {
		return fmt.Errorf("requirement coverage source identity disagrees with the admitted source")
	}
	digest, err := requirementsourceadmission.SourceDigest(source)
	if err != nil {
		return err
	}
	if output["sourceDigest"] != digest {
		return fmt.Errorf("requirement coverage source digest disagrees with the admitted source")
	}
	retainedNonClaims := map[string]struct{}{}
	for _, raw := range output["nonClaims"].([]any) {
		retainedNonClaims[raw.(string)] = struct{}{}
	}
	for _, boundary := range source.NonClaims() {
		if _, retained := retainedNonClaims[boundary]; !retained {
			return fmt.Errorf("requirement coverage dropped an admitted source non-claim")
		}
	}
	byID := map[string]requirementsourceadmission.Requirement{}
	ownerSet := map[string]struct{}{}
	for _, raw := range output["coverageBasis"].(map[string]any)["ownerIds"].([]any) {
		ownerSet[raw.(string)] = struct{}{}
	}
	expectedRows := map[string]struct{}{}
	expectedOutOfScope := []any{}
	for _, requirement := range source.Requirements() {
		byID[requirement.RequirementID] = requirement
		if _, selected := ownerSet[requirement.OwnerID]; selected {
			expectedRows[requirement.RequirementID] = struct{}{}
		} else if output["completenessDeclaration"] == "full_repository" {
			expectedOutOfScope = append(expectedOutOfScope, map[string]any{
				"ownerId": requirement.OwnerID, "requirementId": requirement.RequirementID,
			})
		}
	}
	sort.Slice(expectedOutOfScope, func(left, right int) bool {
		return expectedOutOfScope[left].(map[string]any)["requirementId"].(string) < expectedOutOfScope[right].(map[string]any)["requirementId"].(string)
	})
	if !reflect.DeepEqual(output["coverageBasis"].(map[string]any)["fullRepositoryOutOfScopeSourceRequirements"], expectedOutOfScope) {
		return fmt.Errorf("requirement coverage out-of-scope source requirements disagree with the admitted source")
	}
	links := []requirementsourceadmission.ScenarioLink{}
	definitionRefs := []string{}
	seenRows := map[string]struct{}{}
	for _, raw := range output["requirementCoverage"].([]any) {
		row := raw.(map[string]any)
		id := row["requirementId"].(string)
		if _, selected := expectedRows[id]; !selected {
			return fmt.Errorf("requirement coverage row is outside the admitted owner scope")
		}
		seenRows[id] = struct{}{}
		requirement, exists := byID[id]
		if !exists {
			return fmt.Errorf("requirement coverage row is outside its admitted source")
		}
		value := requirementsourceadmission.RequirementValue(requirement)
		for _, key := range []string{"claimLevel", "externalNonClaimRefs", "invariant", "nonClaimRefs", "nonClaims", "ownerId", "requirementId", "sharedPremises"} {
			if !reflect.DeepEqual(row[key], value[key]) {
				return fmt.Errorf("requirement coverage row disagrees with its admitted source at %s", key)
			}
		}
		if row["lifecycleState"] != requirement.Lifecycle.State || row["specPath"] != source.RequirementsPath() {
			return fmt.Errorf("requirement coverage row disagrees with its admitted source lifecycle or path")
		}
		definitionRefs = append(definitionRefs, requirement.NonClaimRefs...)
		for _, rawScenario := range row["scenarios"].([]any) {
			scenario := rawScenario.(map[string]any)
			links = append(links, requirementsourceadmission.ScenarioLink{RequirementID: id, ScenarioID: scenario["scenarioId"].(string)})
		}
	}
	if len(seenRows) != len(expectedRows) {
		return fmt.Errorf("requirement coverage rows omit an admitted in-scope requirement")
	}
	if err := requirementsourceadmission.AdmitScenarioLinks([]requirementsourceadmission.Source{source}, links); err != nil {
		return fmt.Errorf("requirement coverage scenario disagrees with its admitted source: %w", err)
	}
	definitions, err := source.NonClaimDefinitions().Select(definitionRefs)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(output["nonClaimDefinitions"], definitions.Value()) {
		return fmt.Errorf("requirement coverage non-claim definitions disagree with the admitted source")
	}
	return nil
}
