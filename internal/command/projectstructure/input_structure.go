package projectstructure

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var inputKeys = []string{"bootstrap", "nonClaims", "paths", "repoProfileScaffold", "scaffoldId", "schemaVersion", "workflow"}

// Scaffold-owned operands read without a member inventory; extra members are
// ignored by native admission and therefore remain open here.
var pathKeys = []string{"bootstrapInputPath", "repoProfileScaffoldInputPath", "workflowInputPath"}
var workflowKeys = []string{"nonClaims", "scenario", "workflowId"}

// Bootstrap members that this composition reads or turns into materialized
// file paths. Their refusal here is stricter than the standalone bootstrap,
// which reports these members as failed instead of refusing input.
var bootstrapPathKeys = []string{"adoptionGuidancePath", "adoptionProfilePath", "witnessPlanInputPath"}

func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	properties := map[string]any{
		"bootstrap": bootstrapInputStructure(), "nonClaims": fragment(jsonshape.Array(text, 1)),
		"paths":               openObject(pathKeys, map[string]jsonshape.Shape{"bootstrapInputPath": text, "repoProfileScaffoldInputPath": text, "workflowInputPath": text}, "Native scaffold paths are trimmed safe repository-relative POSIX paths; members outside this inventory are ignored."),
		"repoProfileScaffold": scaffoldprofileplan.InputStructure(), "scaffoldId": fragment(identifierShape()),
		"schemaVersion": fragment(jsonshape.IntegerLiteral(1)),
		"workflow": openObject(workflowKeys, map[string]jsonshape.Shape{
			"nonClaims": jsonshape.Array(text, 1), "scenario": jsonshape.StringLiteral("new_repository"), "workflowId": identifierShape(),
		}, "Only scenario, workflowId and nonClaims are read; other workflow members are ignored. Duplicate workflow claims are merged; claims repeating adoption-workflow builtin claims are refused natively."),
	}
	if len(properties) != len(inputKeys) {
		panic("project structure input differs from its member inventory")
	}
	required := make([]any, 0, len(inputKeys))
	for _, key := range inputKeys {
		required = append(required, key)
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"properties": properties, "required": required,
		"description": "All seven root members are required and the root is closed. repoProfileScaffold reuses the scaffold-profile-plan input structure; bootstrap reuses the direct gradual-adoption-bootstrap input structure narrowed to the members this composition reads or materializes. Root and workflow nonClaims trim to nonempty secret-safe text and duplicates are merged. Native admission also owns IDs without secret/timestamp components, safe path grammar and privacy, the detached secret-shaped bootstrap snapshot, unique materialized file paths and builtin nonClaim collisions. Path drift between the repository profile, bootstrap and owner route, failed bootstrap reports and blocked workflow plans produce failed scaffold reports rather than refusal. schemaVersion requires the literal integer token 1 while the semantic contract is v2.",
	}
}

// The standalone bootstrap owner remains authoritative for every other member.
func bootstrapInputStructure() map[string]any {
	text, path := jsonshape.NonBlankString(), jsonshape.StringGrammar(`[\s\S]+`)
	schema := gradualadoption.BootstrapInputStructure()
	properties := schema["properties"].(map[string]any)
	properties["module"] = openObject([]string{"specPath"}, map[string]jsonshape.Shape{"specPath": path}, "The module specPath becomes a materialized file path; other module members keep bootstrap failure-collecting evaluation.")
	properties["paths"] = openObject(bootstrapPathKeys, map[string]jsonshape.Shape{
		"adoptionGuidancePath": text, "adoptionProfilePath": path, "witnessPlanInputPath": text,
	}, "These paths become workflow refs or materialized files; workflow refs are trimmed. Other path members keep bootstrap failure-collecting evaluation.")
	properties["proofBindingPath"] = fragment(text)
	repository := properties["repository"].(map[string]any)
	repository["properties"] = map[string]any{"profilePath": fragment(path)}
	repository["required"] = []any{"profilePath"}
	repository["description"] = "The repository profilePath becomes a materialized file path; other repository members are forwarded into the generated adoption profile."
	required := slices.Clone(schema["required"].([]any))
	for _, key := range []string{"module", "paths", "proofBindingPath"} {
		if !slices.Contains(required, any(key)) {
			required = append(required, key)
		}
	}
	slices.SortFunc(required, func(a, b any) int {
		if a.(string) < b.(string) {
			return -1
		}
		return 1
	})
	schema["required"] = required
	schema["description"] = "Direct gradual-adoption-bootstrap input as composed by scaffold-project-structure. Members materialized as scaffold files or workflow refs are required here; empty or duplicate materialized paths refuse the scaffold. All other bootstrap admission, failure-collecting evaluation and secret-shaped snapshot rejection remain owned by the bootstrap command."
	return schema
}

func openObject(keys []string, fields map[string]jsonshape.Shape, description string) map[string]any {
	properties := make([]jsonshape.Property, 0, len(keys))
	for _, key := range keys {
		shape, ok := fields[key]
		if !ok {
			panic("open structure omits a member")
		}
		properties = append(properties, jsonshape.Required(key, shape))
	}
	if len(properties) != len(fields) {
		panic("open structure differs from its member inventory")
	}
	schema := fragment(jsonshape.Object(properties...))
	schema["additionalProperties"] = true
	schema["description"] = description
	return schema
}

func identifierShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func fragment(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}
