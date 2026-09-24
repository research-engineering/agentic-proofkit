package requirementcoverageview

import (
	"fmt"
	"reflect"

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
	byID := map[string]requirementsourceadmission.Requirement{}
	for _, requirement := range source.Requirements() {
		byID[requirement.RequirementID] = requirement
	}
	links := []requirementsourceadmission.ScenarioLink{}
	definitionRefs := []string{}
	for _, raw := range output["requirementCoverage"].([]any) {
		row := raw.(map[string]any)
		id := row["requirementId"].(string)
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
