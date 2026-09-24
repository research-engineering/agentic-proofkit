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
	variant    string
}

// These are ownership links, not copies of the child schema or native policy.
func nativeChildBindings() []nativeChildBinding {
	return []nativeChildBinding{
		{"adopt-materialize-apply", "input", sourceV2DefinitionID, [][]string{{"requirementSources", "*"}}, ""},
		{"adopt-materialize-plan", "input", sourceV2DefinitionID, [][]string{{"requirementSources", "*"}}, ""},
		{"requirement-coverage-input-compose", "input", sourceV2DefinitionID, [][]string{{"requirementSource"}}, ""},
		{"requirement-coverage-input-compose", "output", sourceV2DefinitionID, [][]string{{"requirementSource"}}, ""},
		{"requirement-coverage-view", "input", sourceV2DefinitionID, [][]string{{"requirementSource"}}, ""},
		{"requirement-impact-input-compose", "input", sourceV2DefinitionID, [][]string{{"baseRequirementSources", "*"}, {"currentRequirementSources", "*"}}, ""},
		{"requirement-authoring-plan", "input", sourceV2DefinitionID, [][]string{{"currentRequirementSource"}, {"candidateRequirementSource"}}, ""},
		{"requirement-authoring-plan", "output", sourceV2DefinitionID, [][]string{{"nonAuthoritativeAdmissionPreview", "requirementSourcePreview"}}, ""},
		{"requirement-source-transition", "input", sourceV2DefinitionID, [][]string{{"previous"}, {"next"}}, ""},
		{"test-evidence-inventory", "input", sourceV2DefinitionID, [][]string{{"requirementSource"}}, "03-proof-binding-derived"},
		{"requirement-context-compose", "output", sourceV2DefinitionID, [][]string{{"projections", "requirementSources", "*"}}, ""},
		{"requirement-browser-server", "input", sourceV2DefinitionID, [][]string{{"requirementSource"}}, ""},
		{"requirement-browser-server", "input", sourceV2DefinitionID, [][]string{{"context", "projections", "requirementSources", "*"}}, "07-workspace"},
		{"requirement-browser-server", "input", sourceV2DefinitionID, [][]string{{}}, "05-source"},
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
			binding := map[string]any{
				"relationKind": "nested_definition", "pathSegments": segments,
				"definitionRef": owner.definition, "definitionDigest": definition.Digest,
			}
			if owner.variant != "" {
				binding["variantId"] = owner.variant
			}
			result = append(result, binding)
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
		found := false
		for _, variant := range variants {
			variantRecord := variant.(map[string]any)
			if variantID, scoped := raw.(map[string]any)["variantId"]; scoped && variantRecord["variantId"] != variantID {
				continue
			}
			allowed := variantRecord["allowedFields"].([]any)
			if len(path) == 0 {
				childVariants := definitions[raw.(map[string]any)["definitionRef"].(string)].Content["fieldTree"].(map[string]any)["variants"].([]any)
				if len(childVariants) != 1 || !reflect.DeepEqual(allowed, childVariants[0].(map[string]any)["allowedFields"]) ||
					!reflect.DeepEqual(variantRecord["requiredFields"], childVariants[0].(map[string]any)["requiredFields"]) {
					return fmt.Errorf("%s %s root child binding differs from its source owner", command, direction)
				}
				found = true
			} else if slices.Contains(allowed, any(path[0].(string))) {
				found = true
			}
			if found {
				if schema, complete := variantRecord["schema"].(map[string]any); complete {
					child := definitions[raw.(map[string]any)["definitionRef"].(string)].Content["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
					leaf, err := schemaChildAtPath(schema, path)
					if err != nil || !equalSchemaIgnoringDialect(leaf, child) {
						return fmt.Errorf("%s %s child binding path does not contain its source definition", command, direction)
					}
				}
			}
		}
		if !found {
			return fmt.Errorf("%s %s child binding root field is absent", command, direction)
		}
	}
	return nil
}

func schemaChildAtPath(schema map[string]any, path []any) (map[string]any, error) {
	current := schema
	for _, raw := range path {
		if alternatives, wrapped := current["anyOf"].([]any); wrapped {
			var nonNull map[string]any
			for _, alternative := range alternatives {
				candidate := alternative.(map[string]any)
				if candidate["type"] == "null" {
					continue
				}
				if nonNull != nil {
					return nil, fmt.Errorf("ambiguous child schema union")
				}
				nonNull = candidate
			}
			if nonNull == nil {
				return nil, fmt.Errorf("child schema union has no value")
			}
			current = nonNull
		}
		segment := raw.(string)
		if segment == "*" {
			item, ok := current["items"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("child schema path does not enter an array")
			}
			current = item
			continue
		}
		properties, ok := current["properties"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("child schema path does not enter an object")
		}
		child, ok := properties[segment].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("child schema path is absent")
		}
		current = child
	}
	return current, nil
}

func equalSchemaIgnoringDialect(left, right map[string]any) bool {
	if left == nil || right == nil {
		return false
	}
	a, b := map[string]any{}, map[string]any{}
	for key, value := range left {
		if key != "$schema" {
			a[key] = value
		}
	}
	for key, value := range right {
		if key != "$schema" {
			b[key] = value
		}
	}
	return reflect.DeepEqual(a, b)
}
