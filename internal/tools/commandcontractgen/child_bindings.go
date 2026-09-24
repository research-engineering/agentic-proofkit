package main

import (
	"fmt"
	"reflect"
	"slices"
)

const sourceV2DefinitionID = "proofkit.requirement-source.input.v2.json-schema"

type nativeChildBinding struct {
	command    string
	direction  string
	definition string
	paths      [][]string
}

// These are ownership links, not copies of the child schema or native policy.
func nativeChildBindings() []nativeChildBinding {
	return []nativeChildBinding{
		{"adopt-materialize-apply", "input", sourceV2DefinitionID, [][]string{{"requirementSources", "*"}}},
		{"adopt-materialize-plan", "input", sourceV2DefinitionID, [][]string{{"requirementSources", "*"}}},
		{"requirement-coverage-input-compose", "input", sourceV2DefinitionID, [][]string{{"requirementSource"}}},
		{"requirement-coverage-input-compose", "output", sourceV2DefinitionID, [][]string{{"requirementSource"}}},
		{"requirement-coverage-view", "input", sourceV2DefinitionID, [][]string{{"requirementSource"}}},
		{"requirement-impact-input-compose", "input", sourceV2DefinitionID, [][]string{{"baseRequirementSources", "*"}, {"currentRequirementSources", "*"}}},
	}
}

func childBindingValues(command, direction string, definitions map[string]definitionRecord) ([]any, error) {
	result := []any{}
	for _, owner := range nativeChildBindings() {
		if owner.command != command || owner.direction != direction {
			continue
		}
		definition, ok := definitions[owner.definition]
		if !ok {
			return nil, fmt.Errorf("%s %s child owner is absent", command, direction)
		}
		for _, path := range owner.paths {
			segments := make([]any, len(path))
			for index, segment := range path {
				segments[index] = segment
			}
			result = append(result, map[string]any{
				"relationKind": "nested_definition", "pathSegments": segments,
				"definitionRef": owner.definition, "definitionDigest": definition.Digest,
			})
		}
	}
	return result, nil
}

func admitChildBindings(command, direction string, contract map[string]any, root definitionRecord, definitions map[string]definitionRecord) error {
	expected, err := childBindingValues(command, direction, definitions)
	if err != nil {
		return err
	}
	actual, present := contract["childDefinitionBindings"]
	if len(expected) == 0 {
		if present {
			return fmt.Errorf("%s %s has unowned child definition bindings", command, direction)
		}
		return nil
	}
	if !present || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("%s %s child definition bindings differ from native owners", command, direction)
	}
	variants := root.Content["fieldTree"].(map[string]any)["variants"].([]any)
	for _, raw := range expected {
		path := raw.(map[string]any)["pathSegments"].([]any)
		field := path[0].(string)
		found := false
		for _, variant := range variants {
			allowed := variant.(map[string]any)["allowedFields"].([]any)
			if slices.Contains(allowed, any(field)) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s %s child binding root field is absent", command, direction)
		}
	}
	return nil
}
