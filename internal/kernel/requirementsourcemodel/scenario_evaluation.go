package requirementsourcemodel

type scenarioEvaluationCost struct {
	Items     uint64
	TextBytes uint64
}

func preflightScenarioEvaluationBudget(draft Draft, limits Limits) error {
	cost, overflow := estimateScenarioEvaluationCost(draft)
	if overflow || cost.Items > uint64(limits.MaxScenarioEvaluations) {
		return invalid("scenario_evaluation_budget_exceeded", "scenarios")
	}
	if cost.TextBytes > uint64(limits.MaxScenarioEvaluationBytes) {
		return invalid("scenario_evaluation_text_budget_exceeded", "scenarios")
	}
	return nil
}

func estimateScenarioEvaluationCost(draft Draft) (scenarioEvaluationCost, bool) {
	cost := scenarioEvaluationCost{}
	for _, scenario := range draft.Scenarios {
		exampleCount := uint64(len(scenario.Examples))
		observationCount := uint64(len(scenario.ExpectedObservations) + len(scenario.ForbiddenObservations))
		if !addScenarioCost(&cost.Items, observationCount, exampleCount) {
			return cost, true
		}
		valueBytes := map[string]uint64{}
		valueCounts := map[string]uint64{}
		for _, example := range scenario.Examples {
			for parameter, value := range example.Values {
				bytes := valueBytes[parameter]
				if !addScenarioCost(&bytes, uint64(len(value)), 1) {
					return cost, true
				}
				valueBytes[parameter] = bytes
				valueCounts[parameter]++
			}
		}
		observations := append([]string{}, scenario.ExpectedObservations...)
		observations = append(observations, scenario.ForbiddenObservations...)
		for _, observation := range observations {
			bytes, overflow := instantiatedObservationBytes(observation, exampleCount, valueBytes, valueCounts)
			if overflow || !addScenarioCost(&cost.TextBytes, bytes, 1) {
				return cost, true
			}
		}
	}
	return cost, false
}

func instantiatedObservationBytes(template string, exampleCount uint64, valueBytes map[string]uint64, valueCounts map[string]uint64) (uint64, bool) {
	matches := parameterReferencePattern.FindAllStringSubmatchIndex(template, -1)
	staticBytes := uint64(len(template))
	for _, match := range matches {
		staticBytes -= uint64(match[1] - match[0])
	}
	total := uint64(0)
	if !addScenarioCost(&total, staticBytes, exampleCount) {
		return 0, true
	}
	for _, match := range matches {
		parameter := template[match[2]:match[3]]
		if !addScenarioCost(&total, valueBytes[parameter], 1) {
			return 0, true
		}
		missingCount := exampleCount - valueCounts[parameter]
		if !addScenarioCost(&total, uint64(match[1]-match[0]), missingCount) {
			return 0, true
		}
	}
	return total, false
}

func addScenarioCost(total *uint64, value uint64, multiplier uint64) bool {
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

func validateInstantiatedObservationDisjoint(expected []string, forbidden []string, examples []Example, path string) error {
	for _, example := range examples {
		expectedValues := make(map[string]struct{}, len(expected))
		for _, observation := range expected {
			expectedValues[instantiateScenarioObservation(observation, example.Values)] = struct{}{}
		}
		for _, observation := range forbidden {
			if _, contradiction := expectedValues[instantiateScenarioObservation(observation, example.Values)]; contradiction {
				return invalid("contradictory_instantiated_observation", path)
			}
		}
	}
	return nil
}

func instantiateScenarioObservation(template string, values map[string]ScenarioValue) string {
	return parameterReferencePattern.ReplaceAllStringFunc(template, func(reference string) string {
		matches := parameterReferencePattern.FindStringSubmatch(reference)
		if len(matches) != 2 {
			return reference
		}
		value, exists := values[matches[1]]
		if !exists {
			return reference
		}
		return string(value)
	})
}
