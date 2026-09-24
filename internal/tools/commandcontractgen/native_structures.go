package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementauthoringplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type nativeStructure struct {
	id           string
	direction    string
	predecessors []string
	commands     []string
	schema       func() (map[string]any, error)
	variants     []nativeStructureVariant
	wireVersion  json.Number
}

type nativeStructureVariant struct {
	id     string
	when   string
	schema func() (map[string]any, error)
}

// This registry binds native structure owners to their exact public consumers.
// It is not a second schema interpreter or a replacement for native semantics.
func nativeStructures() []nativeStructure {
	return []nativeStructure{{
		id:           "proofkit.requirement-bindings.input.v1.json-schema",
		direction:    "input",
		predecessors: []string{"proofkit.requirement-bindings.input.v1.root-shape"},
		commands:     []string{"evidence-graph", "proof-slice", "requirement-bindings"},
		schema:       func() (map[string]any, error) { return requirementbinding.InputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source.input.v2.json-schema",
		direction:    "input",
		predecessors: []string{"proofkit.requirement-source-admission.input.v1.root-shape", "proofkit.requirement-source-view.input.v1.root-shape"},
		commands:     []string{"requirement-source-admission", "requirement-source-view"},
		schema: func() (map[string]any, error) {
			return requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
		},
	}, {
		id:           "proofkit.requirement-source-admission.output.v2.json-schema",
		direction:    "output",
		predecessors: []string{"proofkit.requirement-source-admission.output.v2.root-shape"},
		commands:     []string{"requirement-source-admission"},
		schema:       func() (map[string]any, error) { return requirementsourceadmission.OutputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source-view.output.v2.json-schema",
		direction:    "output",
		predecessors: []string{"proofkit.requirement-source-view.output.v2.root-shape"},
		commands:     []string{"requirement-source-view"},
		schema:       func() (map[string]any, error) { return requirementsourceview.OutputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source-transition.input.v2.json-schema",
		direction:    "input",
		predecessors: []string{"proofkit.requirement-source-transition.input.v2.root-shape"},
		commands:     []string{"requirement-source-transition"},
		schema:       func() (map[string]any, error) { return requirementsourcetransition.InputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source-transition.output.v2.json-schema",
		direction:    "output",
		predecessors: []string{"proofkit.requirement-source-transition.output.v2.root-shape"},
		commands:     []string{"requirement-source-transition"},
		schema:       func() (map[string]any, error) { return requirementsourcetransition.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-authoring-plan.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-authoring-plan.input.v2.root-shape"}, commands: []string{"requirement-authoring-plan"},
		schema: func() (map[string]any, error) { return requirementauthoringplan.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-authoring-plan.output.v3.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-authoring-plan.output.v3.root-shape"}, commands: []string{"requirement-authoring-plan"},
		schema: func() (map[string]any, error) { return requirementauthoringplan.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-context-compose.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-context-compose.input.v2.root-shape"}, commands: []string{"requirement-context-compose"},
		schema: func() (map[string]any, error) { return requirementcontext.CatalogInputStructure(), nil },
	}, {
		id: "proofkit.requirement-spec-tree.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-spec-tree.input.v1.root-shape", "proofkit.requirement-spec-tree-view.input.v1.root-shape"},
		commands:     []string{"requirement-spec-tree", "requirement-spec-tree-view"},
		schema:       func() (map[string]any, error) { return requirementspectree.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-coverage-view.output.v4.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-coverage-view.output.v4.root-shape"}, commands: []string{"requirement-coverage-view"},
		wireVersion: json.Number("4"),
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope", schema: agentEnvelopeRootStructure},
			{id: "02-report", when: "without --agent-envelope", schema: func() (map[string]any, error) { return requirementcoverageview.OutputStructure(), nil }},
		},
	}, {
		id: "proofkit.requirement-context-compose.output.v4.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-context-compose.output.v4.root-shape"}, commands: []string{"requirement-context-compose"},
		schema: func() (map[string]any, error) { return requirementcontext.CatalogSnapshotStructure(), nil },
	}, {
		id: "proofkit.requirement-context-slice.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-context-slice.input.v2.root-shape"}, commands: []string{"requirement-context-slice"},
		schema: func() (map[string]any, error) { return requirementcontext.SliceInputStructure(), nil },
	}, {
		id: "proofkit.requirement-semantic-diff.input.v3.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-semantic-diff.input.v3.root-shape"}, commands: []string{"requirement-semantic-diff"},
		schema: func() (map[string]any, error) { return requirementdiff.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-traceability-graph.input.v3.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-traceability-graph.input.v3.root-shape"}, commands: []string{"requirement-traceability-graph"},
		schema: func() (map[string]any, error) { return requirementgraph.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-context-slice.output.v2.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-context-slice.output.v2.root-shape"}, commands: []string{"requirement-context-slice"},
		schema: func() (map[string]any, error) { return requirementcontext.SliceOutputStructure(), nil },
	}, {
		id: "proofkit.requirement-semantic-diff.output.v3.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-semantic-diff.output.v3.root-shape"}, commands: []string{"requirement-semantic-diff"},
		schema: func() (map[string]any, error) { return requirementdiff.OutputStructure(), nil },
	}}
}

func (owner nativeStructure) definition() (map[string]any, error) {
	if owner.direction != "input" && owner.direction != "output" {
		return nil, fmt.Errorf("native structure has an invalid direction")
	}
	variants := owner.variants
	if len(variants) == 0 {
		variants = []nativeStructureVariant{{id: "01-root", when: "default JSON mode", schema: owner.schema}}
	}
	wireVariants := make([]any, 0, len(variants))
	for _, variant := range variants {
		if variant.id == "" || variant.when == "" || variant.schema == nil {
			return nil, fmt.Errorf("native structure %s has an invalid variant", owner.id)
		}
		schema, err := variant.schema()
		if err != nil {
			return nil, fmt.Errorf("native structure %s: %w", owner.id, err)
		}
		root, err := nativeStructureRoot(schema)
		if err != nil {
			return nil, err
		}
		properties := root["properties"].(map[string]any)
		allowed := []any{}
		for _, key := range sortedKeys(properties) {
			allowed = append(allowed, key)
		}
		wireVariants = append(wireVariants, map[string]any{
			"variantId": variant.id, "when": []any{variant.when}, "rootKind": "object",
			"allowedFields": allowed, "requiredFields": root["required"], "schema": schema,
		})
	}
	record := map[string]any{
		"definitionId": owner.id, "schemaVersion": json.Number("1"),
		"rootType": "object", "closed": true, "definitionRefs": []any{},
		"fieldTree": map[string]any{
			"kind": "structural_json_schema",
			"nonClaims": []any{
				"Structural JSON Schema does not replace native canonicalization, semantic admission, or numeric representation checks.",
				"Structural JSON Schema does not replace direct public-CLI runtime witnesses for variant selection.",
			},
			"variants": wireVariants,
		},
	}
	encoded, err := canonicalJSON(record)
	if err != nil {
		return nil, err
	}
	record["canonicalDigest"] = sha256Digest(encoded)
	return record, nil
}

func (owner nativeStructure) contractVersion(definition map[string]any) (json.Number, error) {
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if owner.wireVersion != "" {
		for _, raw := range variants {
			version, err := nativeSchemaVersion(raw.(map[string]any)["schema"].(map[string]any))
			if err != nil {
				return "", err
			}
			if version == owner.wireVersion {
				return version, nil
			}
		}
		return "", fmt.Errorf("native structure %s has no variant with wire version %s", owner.id, owner.wireVersion)
	}
	return nativeSchemaVersion(variants[0].(map[string]any)["schema"].(map[string]any))
}

// The generic envelope owner fixes root keys and types; its nested records
// retain their separately admitted semantics.
func agentEnvelopeRootStructure() (map[string]any, error) {
	output := agentenvelope.Build(agentenvelope.Input{})
	properties := map[string]any{}
	required := []any{}
	for _, key := range sortedKeys(output) {
		var field map[string]any
		switch value := output[key].(type) {
		case string:
			field = map[string]any{"type": "string"}
		case []any:
			field = map[string]any{"type": "array"}
		case map[string]any:
			field = map[string]any{"type": "object"}
		case int:
			if key != "schemaVersion" || value != 1 {
				return nil, fmt.Errorf("agent envelope has an unexpected integer root field")
			}
			field = map[string]any{"type": "integer", "const": json.Number("1")}
		default:
			return nil, fmt.Errorf("agent envelope has an unsupported root field")
		}
		properties[key] = field
		required = append(required, key)
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "additionalProperties": false,
		"properties": properties, "required": required,
	}, nil
}

func (owner nativeStructure) summary(version json.Number) []any {
	return []any{"schemaVersion=" + version.String(), "structural JSON Schema definition " + owner.id + "; canonicalization and semantic validity remain native admission obligations"}
}

func nativeSchemaVersion(schema map[string]any) (json.Number, error) {
	root, err := nativeStructureRoot(schema)
	if err != nil {
		return "", err
	}
	return nativeObjectSchemaVersion(root)
}

// A structural sum retains its full schema. Only its common root summary is
// projected; branches with different roots or wire versions need separate owners.
func nativeStructureRoot(schema map[string]any) (map[string]any, error) {
	if schema["type"] == "object" {
		if _, err := nativeObjectSchemaVersion(schema); err != nil {
			return nil, err
		}
		return schema, nil
	}
	for key := range schema {
		if key != "$schema" && key != "oneOf" {
			return nil, fmt.Errorf("native structure requires a closed object projection or object alternatives")
		}
	}
	alternatives, ok := schema["oneOf"].([]any)
	if !ok || len(alternatives) < 2 {
		return nil, fmt.Errorf("native structure requires at least two closed object alternatives")
	}
	var root map[string]any
	var version json.Number
	for _, raw := range alternatives {
		branch, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("native structure alternative must be an object schema")
		}
		nextVersion, err := nativeObjectSchemaVersion(branch)
		if err != nil {
			return nil, err
		}
		if root == nil {
			root, version = branch, nextVersion
			continue
		}
		if nextVersion != version || !reflect.DeepEqual(root["required"], branch["required"]) ||
			!slices.Equal(sortedKeys(root["properties"].(map[string]any)), sortedKeys(branch["properties"].(map[string]any))) {
			return nil, fmt.Errorf("native structure alternatives must share root fields and schemaVersion")
		}
	}
	return root, nil
}

func nativeObjectSchemaVersion(schema map[string]any) (json.Number, error) {
	if _, ok := schema["properties"].(map[string]any); !ok || schema["type"] != "object" || schema["additionalProperties"] != false {
		return "", fmt.Errorf("native structure requires a closed object projection")
	}
	properties, _ := schema["properties"].(map[string]any)
	field, _ := properties["schemaVersion"].(map[string]any)
	version, ok := field["const"].(json.Number)
	required, _ := schema["required"].([]any)
	if !ok || field["type"] != "integer" || !slices.Contains(required, any("schemaVersion")) {
		return "", fmt.Errorf("native structure requires a required literal integer schemaVersion")
	}
	number, err := version.Int64()
	if err != nil || number < 1 || version.String() != fmt.Sprint(number) {
		return "", fmt.Errorf("native structure schemaVersion must be a positive canonical integer")
	}
	return version, nil
}

func admitNativeStructureDefinition(id string, record map[string]any) error {
	owner, ok := nativeStructureOwner(id)
	if !ok {
		return fmt.Errorf("contract definition %s has no registered native structural owner", id)
	}
	expected, err := owner.definition()
	if err != nil {
		return err
	}
	actualBytes, err := canonicalJSON(record)
	if err != nil {
		return err
	}
	expectedBytes, err := canonicalJSON(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		return fmt.Errorf("contract definition %s differs from its native structural owner; use --refresh-structures", id)
	}
	return nil
}

func nativeStructureOwner(id string) (nativeStructure, bool) {
	for _, owner := range nativeStructures() {
		if owner.id == id {
			return owner, true
		}
	}
	return nativeStructure{}, false
}

func admitNativeStructureConsumers(contract map[string]any, definitions map[string]definitionRecord) error {
	commands, ok := contract["commands"].([]any)
	if !ok {
		return fmt.Errorf("CLI contract commands must be an array")
	}
	for _, owner := range nativeStructures() {
		seen := map[string]bool{}
		for _, raw := range commands {
			command, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("CLI contract command must be an object")
			}
			name, _ := command["command"].(string)
			for _, direction := range []string{"input", "output"} {
				binding, _ := command[direction+"Contract"].(map[string]any)
				isConsumer := direction == owner.direction && slices.Contains(owner.commands, name)
				usesOwner := binding["rootDefinitionRef"] == owner.id
				if isConsumer != usesOwner {
					return fmt.Errorf("%s %s contract violates native structure consumer ownership", name, direction)
				}
				if isConsumer {
					seen[name] = true
				}
			}
		}
		_, defined := definitions[owner.id]
		if defined != (len(seen) > 0) || (len(seen) != 0 && len(seen) != len(owner.commands)) {
			return fmt.Errorf("native structure %s must have its complete consumer set", owner.id)
		}
		for _, predecessor := range owner.predecessors {
			if _, old := definitions[predecessor]; old {
				return fmt.Errorf("obsolete native structure %s remains", predecessor)
			}
		}
	}
	return nil
}
