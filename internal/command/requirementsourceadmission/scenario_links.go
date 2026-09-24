package requirementsourceadmission

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type ScenarioLink struct {
	RequirementID string
	ScenarioID    string
}

// AdmitScenarioLinks checks source-local membership when independent binding
// and source owners first meet. A missing source body remains reference-only.
func AdmitScenarioLinks(sources []Source, links []ScenarioLink) error {
	byRequirement := map[string]Source{}
	for _, source := range sources {
		if !source.admitted {
			return fmt.Errorf("scenario links require admitted requirement sources")
		}
		for _, requirement := range source.model.Requirements() {
			if _, exists := byRequirement[requirement.RequirementID]; exists {
				return fmt.Errorf("scenario links require unique requirement ownership")
			}
			byRequirement[requirement.RequirementID] = source
		}
	}
	for _, link := range links {
		source, exists := byRequirement[link.RequirementID]
		if !exists {
			return fmt.Errorf("scenario link references a requirement outside admitted sources")
		}
		_, err := requirementsourcemodel.ResolveScenario(source.model, requirementsourcemodel.ScenarioReference{
			SourceID: source.SourceID(), RequirementID: link.RequirementID, ScenarioID: link.ScenarioID,
		})
		if err != nil {
			return fmt.Errorf("scenario link disagrees with its admitted source: %w", err)
		}
	}
	return nil
}
