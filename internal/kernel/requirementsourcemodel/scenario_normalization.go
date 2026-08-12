package requirementsourcemodel

import (
	"sort"
	"strings"
)

func normalizeScenarios(values []Scenario, requirements map[string]AtomicRequirement, vocabulary map[string]struct{}) ([]Scenario, error) {
	result := make([]Scenario, len(values))
	ids := make(map[string]struct{}, len(values))
	for index, value := range values {
		path := indexed("scenarios", index, "")
		scenarioID, err := canonicalID(value.ScenarioID, "SCN-", path+"scenarioId")
		if err != nil {
			return nil, err
		}
		if _, exists := ids[scenarioID]; exists {
			return nil, invalid("duplicate_id", "scenarios")
		}
		requirementIDs, err := normalizeIDs(value.RequirementIDs, "REQ-", path+"requirementIds", false)
		if err != nil {
			return nil, err
		}
		for _, requirementID := range requirementIDs {
			if _, exists := requirements[requirementID]; !exists {
				return nil, invalid("dangling_requirement_ref", path+"requirementIds")
			}
		}
		parameters, err := normalizeParameters(value.Parameters, path+"parameters")
		if err != nil {
			return nil, err
		}
		preconditions, err := normalizeTexts(value.Preconditions, path+"preconditions", false, true)
		if err != nil {
			return nil, err
		}
		actions, err := normalizeOrderedTexts(value.ActionSequence, path+"actionSequence", false)
		if err != nil {
			return nil, err
		}
		expected, err := normalizeTexts(value.ExpectedObservations, path+"expectedObservations", false, true)
		if err != nil {
			return nil, err
		}
		forbidden, err := normalizeTexts(value.ForbiddenObservations, path+"forbiddenObservations", true, true)
		if err != nil {
			return nil, err
		}
		if sortedStringsIntersect(expected, forbidden) {
			return nil, invalid("contradictory_observation", path+"expectedObservations")
		}
		vocabularyRefs, err := normalizeIDs(value.VocabularyRefs, "TERM-", path+"vocabularyRefs", true)
		if err != nil {
			return nil, err
		}
		for _, termID := range vocabularyRefs {
			if _, exists := vocabulary[termID]; !exists {
				return nil, invalid("dangling_vocabulary_ref", path+"vocabularyRefs")
			}
		}
		nonClaimRefs, err := normalizeIDs(value.NonClaimRefs, "NCL-", path+"nonClaimRefs", true)
		if err != nil {
			return nil, err
		}
		statements := append([]string{}, preconditions...)
		statements = append(statements, actions...)
		statements = append(statements, expected...)
		statements = append(statements, forbidden...)
		if err := validateParameterReferences(parameters, statements, path); err != nil {
			return nil, err
		}
		examples, err := normalizeExamples(value.Examples, parameters, path+"examples")
		if err != nil {
			return nil, err
		}
		if err := validateInstantiatedObservationDisjoint(expected, forbidden, examples, path+"expectedObservations"); err != nil {
			return nil, err
		}
		ids[scenarioID] = struct{}{}
		result[index] = Scenario{
			ScenarioID:            scenarioID,
			RequirementIDs:        requirementIDs,
			Parameters:            parameters,
			Preconditions:         preconditions,
			ActionSequence:        actions,
			ExpectedObservations:  expected,
			ForbiddenObservations: forbidden,
			Examples:              examples,
			VocabularyRefs:        vocabularyRefs,
			NonClaimRefs:          nonClaimRefs,
		}
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].ScenarioID < result[right].ScenarioID })
	return result, nil
}

func sortedStringsIntersect(left []string, right []string) bool {
	for leftIndex, rightIndex := 0, 0; leftIndex < len(left) && rightIndex < len(right); {
		switch {
		case left[leftIndex] < right[rightIndex]:
			leftIndex++
		case left[leftIndex] > right[rightIndex]:
			rightIndex++
		default:
			return true
		}
	}
	return false
}

func normalizeParameters(values []string, path string) ([]string, error) {
	result := make([]string, len(values))
	for index, value := range values {
		if !parameterPattern.MatchString(value) {
			return nil, invalid("invalid_parameter", path)
		}
		result[index] = value
	}
	return sortUnique(result, path)
}

func validateParameterReferences(parameters []string, statements []string, path string) error {
	parameterSet := make(map[string]struct{}, len(parameters))
	used := make(map[string]struct{}, len(parameters))
	for _, parameter := range parameters {
		parameterSet[parameter] = struct{}{}
	}
	for _, statement := range statements {
		matches := parameterReferencePattern.FindAllStringSubmatch(statement, -1)
		for _, match := range matches {
			parameter := match[1]
			if _, exists := parameterSet[parameter]; !exists {
				return invalid("unknown_parameter_ref", path)
			}
			used[parameter] = struct{}{}
		}
		withoutKnownRefs := parameterReferencePattern.ReplaceAllString(statement, "")
		if strings.Contains(withoutKnownRefs, "${") {
			return invalid("invalid_parameter_ref", path)
		}
	}
	for _, parameter := range parameters {
		if _, exists := used[parameter]; !exists {
			return invalid("unused_parameter", path)
		}
	}
	return nil
}

func normalizeExamples(values []Example, parameters []string, path string) ([]Example, error) {
	if len(parameters) == 0 && len(values) != 0 {
		return nil, invalid("unexpected_examples", path)
	}
	if len(parameters) != 0 && len(values) < 2 {
		return nil, invalid("insufficient_examples", path)
	}
	result := make([]Example, len(values))
	ids := make(map[string]struct{}, len(values))
	for index, value := range values {
		examplePath := indexed(path, index, "")
		exampleID, err := canonicalID(value.ExampleID, "EX-", examplePath+"exampleId")
		if err != nil {
			return nil, err
		}
		if _, exists := ids[exampleID]; exists {
			return nil, invalid("duplicate_id", path)
		}
		keys := make([]string, 0, len(value.Values))
		for key := range value.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if !equalStrings(keys, parameters) {
			return nil, invalid("example_parameter_mismatch", examplePath+"values")
		}
		items := make(map[string]ScenarioValue, len(keys))
		for _, key := range keys {
			scalar, err := canonicalText(string(value.Values[key]), examplePath+"values."+key, false, false)
			if err != nil {
				return nil, err
			}
			items[key] = ScenarioValue(scalar)
		}
		ids[exampleID] = struct{}{}
		result[index] = Example{ExampleID: exampleID, Values: items}
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].ExampleID < result[right].ExampleID })
	return result, nil
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
