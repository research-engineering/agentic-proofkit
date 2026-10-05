package main

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

const sourceV2DefinitionID = "proofkit.requirement-source.input.v2.json-schema"
const compactV2DefinitionID = "proofkit.compact-proof-contract.input.v2.json-schema"

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
		{"requirement-proof-view", "input", compactV2DefinitionID, [][]string{{}}, "01-compact"},
		{"requirement-browser-server", "input", compactV2DefinitionID, [][]string{{}}, "03-proof-compact"},
		{"requirement-browser-server", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, "01-coverage-compact"},
		{"requirement-coverage-input-compose", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, ""},
		{"requirement-coverage-input-compose", "output", compactV2DefinitionID, [][]string{{"compactProofContract"}}, ""},
		{"requirement-coverage-view", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, ""},
		{"requirement-impact-input-compose", "input", compactV2DefinitionID, [][]string{{"baseCompactProofContract"}, {"currentCompactProofContract"}}, ""},
		{"test-evidence-inventory", "input", compactV2DefinitionID, [][]string{{"compactProofContract"}}, "03-proof-binding-derived"},
		{"requirement-proof-source-set", "output", compactV2DefinitionID, [][]string{{"resolverInput"}}, ""},
		{"selective-gate-obligation-decision-input", "input", "proofkit.receipt-currentness-scope.input.v1.json-schema", [][]string{{"receiptCurrentnessScopeAdmission"}}, ""},
		{"selective-gate-obligation-decision-input", "input", "proofkit.receipt-trust-class.input.v1.json-schema", [][]string{{"receiptTrustClassAdmission"}}, ""},
		{"selective-gate-evidence", "input", "proofkit.receipt-producer-admission.input.v1.json-schema", [][]string{{"producerAdmission"}}, ""},
		{"selective-gate-obligation-decision-input", "input", "proofkit.selective-gate-evidence.input.v1.json-schema", [][]string{{"evidence"}}, ""},
		{"selective-gate-obligation-decision-input", "output", "proofkit.obligation-decision.input.v1.json-schema", [][]string{{}}, ""},
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
					if err != nil || !equalBoundChildSchema(leaf, child) {
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

// An optional child can explicitly admit null without changing the nonnull
// child owner. Admit only the exact two-branch wrapper, never an extra domain.
func equalBoundChildSchema(leaf, child map[string]any) bool {
	if equalSchemaIgnoringDialect(leaf, child) {
		return true
	}
	if len(leaf) != 1 {
		return false
	}
	for _, keyword := range []string{"anyOf", "oneOf"} {
		alternatives, ok := leaf[keyword].([]any)
		if !ok || len(alternatives) != 2 {
			continue
		}
		for index, raw := range alternatives {
			null, ok := raw.(map[string]any)
			other, otherOK := alternatives[1-index].(map[string]any)
			if ok && otherOK && len(null) == 1 && null["type"] == "null" && equalSchemaIgnoringDialect(other, child) {
				return true
			}
		}
	}
	return false
}

func schemaChildAtPath(schema map[string]any, path []any) (map[string]any, error) {
	current := schema
	for _, raw := range path {
		var err error
		current, err = localSchemaResource(schema, current)
		if err != nil {
			return nil, err
		}
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
		current, err = localSchemaResource(schema, current)
		if err != nil {
			return nil, err
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
	current, err := localSchemaResource(schema, current)
	if err != nil {
		return nil, err
	}
	for _, keyword := range []string{"anyOf", "oneOf"} {
		alternatives, ok := current[keyword].([]any)
		if len(current) != 1 || !ok {
			continue
		}
		resolved := make([]any, len(alternatives))
		for i, raw := range alternatives {
			branch, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("child schema union member is not an object")
			}
			resolved[i], err = localSchemaResource(schema, branch)
			if err != nil {
				return nil, err
			}
		}
		return map[string]any{keyword: resolved}, nil
	}
	return current, nil
}

// Resolve only a pure alias to one directly named local definition. This does
// not evaluate schemas, fetch resources, or rewrite the child's own references.
func localSchemaResource(root, value map[string]any) (map[string]any, error) {
	raw, present := value["$ref"]
	if !present {
		return value, nil
	}
	ref, ok := raw.(string)
	if !ok || ref == "" || len(value) != 1 {
		return nil, fmt.Errorf("child schema alias must contain only a resource reference")
	}
	name, local := strings.CutPrefix(ref, "#/$defs/")
	if !local || name == "" || strings.ContainsAny(name, "/%~") {
		return nil, fmt.Errorf("child schema alias must name one direct local definition")
	}
	definitions, _ := root["$defs"].(map[string]any)
	found, ok := definitions[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("child schema resource is not defined locally")
	}
	if _, aliases := found["$ref"]; aliases {
		return nil, fmt.Errorf("child schema resource must be materialized")
	}
	return found, nil
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
