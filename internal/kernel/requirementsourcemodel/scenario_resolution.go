package requirementsourcemodel

import "sort"

// ScenarioReference is a lookup identity, not another authored scenario owner.
type ScenarioReference struct {
	SourceID      string
	RequirementID string
	ScenarioID    string
}

type ScenarioResolution struct {
	Reference ScenarioReference
	// A nil body means the source declares no body for this reference. It does
	// not synthesize behavior or establish the validity of an execution binding.
	Body *Scenario
}

// ResolveScenario preserves source scope and requirement membership while
// leaving witness selection and execution authority with their own owners.
func ResolveScenario(source Model, reference ScenarioReference) (ScenarioResolution, error) {
	for _, field := range []struct{ value, path, prefix string }{
		{reference.SourceID, "reference.sourceId", ""},
		{reference.RequirementID, "reference.requirementId", "REQ-"},
		{reference.ScenarioID, "reference.scenarioId", ""},
	} {
		value, err := canonicalID(field.value, field.prefix, field.path)
		if err != nil || value != field.value {
			return ScenarioResolution{}, invalid("invalid_id", field.path)
		}
	}
	if reference.SourceID != source.atomic.SourceID {
		return ScenarioResolution{}, invalid("scenario_source_mismatch", "reference.sourceId")
	}
	requirements := source.atomic.Requirements
	requirementIndex := sort.Search(len(requirements), func(index int) bool {
		return requirements[index].RequirementID >= reference.RequirementID
	})
	if requirementIndex == len(requirements) || requirements[requirementIndex].RequirementID != reference.RequirementID {
		return ScenarioResolution{}, invalid("unknown_requirement", "reference.requirementId")
	}

	scenarios := source.atomic.Scenarios
	scenarioIndex := sort.Search(len(scenarios), func(index int) bool {
		return scenarios[index].ScenarioID >= reference.ScenarioID
	})
	if scenarioIndex == len(scenarios) || scenarios[scenarioIndex].ScenarioID != reference.ScenarioID {
		return ScenarioResolution{Reference: reference}, nil
	}
	scenario := scenarios[scenarioIndex]
	memberIndex := sort.SearchStrings(scenario.RequirementIDs, reference.RequirementID)
	if memberIndex == len(scenario.RequirementIDs) || scenario.RequirementIDs[memberIndex] != reference.RequirementID {
		return ScenarioResolution{}, invalid("scenario_requirement_mismatch", "reference.requirementId")
	}
	body := cloneScenarios(scenarios[scenarioIndex : scenarioIndex+1])[0]
	return ScenarioResolution{Reference: reference, Body: &body}, nil
}
