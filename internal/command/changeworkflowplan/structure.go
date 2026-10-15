package changeworkflowplan

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// Structure helpers project the admitted workflow vocabulary. They do not
// interpret caller input; admission, closure and decision remain native.

func workflowRefIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func workflowRefIDsShape(minimum, maximum int) jsonshape.Shape {
	return jsonshape.BoundedArray(workflowRefIDShape(), minimum, maximum)
}

func workflowDigestShape() jsonshape.Shape {
	return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
}

// Native SHA256Ref trims the whole value and then the hexadecimal remainder,
// so admitted digest text may carry surrounding Unicode white space.
func workflowInputDigestShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[` + space + `]*sha256:[` + space + `]*[0-9a-f]{64}[` + space + `]*`
	})
}

// Canonical POSIX syntax, UTF-8 byte length, privacy and display safety are
// native path predicates; code points are a necessary bound for the bytes.
func workflowPathShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(`[\s\S]+`, maxPathBytes)
}

func workflowStageIDs() []string {
	ids := make([]string, len(workflowCatalog.Stages))
	for index, stage := range workflowCatalog.Stages {
		ids[index] = stage.ID
	}
	return ids
}

// The core declaration bounds membership and length; the published projection
// refines every such list to the ordered catalog prefix it denotes.
func workflowStagePrefixShape(minimum, maximum int) jsonshape.Shape {
	return jsonshape.BoundedArray(jsonshape.Enum(setOf(workflowStageIDs()...)), minimum, maximum)
}

func workflowCheckpointStates() map[string]struct{} {
	states := map[string]struct{}{}
	for _, definition := range workflowCatalog.CheckpointActions {
		states[definition.State] = struct{}{}
	}
	return states
}

func workflowContextRefShape(input bool) jsonshape.Shape {
	digest := workflowDigestShape()
	if input {
		digest = workflowInputDigestShape()
	}
	return jsonshape.RequiredObject(contextRefFields, map[string]jsonshape.Shape{
		"artifactPath":     workflowPathShape(),
		"dependencyRefIds": workflowRefIDsShape(0, maxDependenciesPerRef),
		"refId":            workflowRefIDShape(),
		"refKind":          jsonshape.Enum(contextRefKinds),
		"subjectDigest":    digest,
	})
}

// checkpointFieldShapes covers the union of every native checkpoint variant.
func checkpointFieldShapes() map[string]jsonshape.Shape {
	return map[string]jsonshape.Shape{
		"assessmentSubjectDigest": workflowInputDigestShape(),
		"findingRefs":             workflowRefIDsShape(1, maxFindings),
		"state":                   jsonshape.Enum(workflowCheckpointStates()),
		"subjectDigest":           workflowInputDigestShape(),
		"subjectRefId":            workflowRefIDShape(),
	}
}

func checkpointInputShape() jsonshape.Shape {
	fields := checkpointFieldShapes()
	names := map[string]struct{}{}
	for _, stage := range workflowCatalog.Stages {
		for _, definition := range workflowCatalog.CheckpointActions {
			for _, name := range checkpointFieldNames(definition, stage) {
				names[name] = struct{}{}
			}
		}
	}
	keys := sortedSet(names)
	optional := make([]string, 0, len(keys))
	for _, key := range keys {
		if key != "state" {
			optional = append(optional, key)
		}
	}
	return jsonshape.ObjectFromKeys(keys, fields, optional...)
}

// InputShape is the jsonshape core of InputStructure, before the stage-prefix,
// duplicate-free reference-list and per-stage checkpoint-variant refinements.
func InputShape() jsonshape.Shape {
	return jsonshape.RequiredObject(inputFields, map[string]jsonshape.Shape{
		"checkpoint":              jsonshape.Nullable(checkpointInputShape()),
		"completedStageIds":       workflowStagePrefixShape(0, len(workflowCatalog.Stages)),
		"contextRefs":             jsonshape.BoundedArray(workflowContextRefShape(true), 0, maxCandidateContextRefs),
		"governingAuthorityRefId": jsonshape.Nullable(workflowRefIDShape()),
		"requiredContextRefIds":   workflowRefIDsShape(0, maxRequiredContextRefs),
		"schemaVersion":           jsonshape.IntegerLiteral(1),
	})
}

// InputStructure describes every snapshot native structural admission accepts.
func InputStructure() map[string]any {
	schema := refineWorkflowStructure(InputShape().JSONSchema())
	schema["allOf"] = checkpointStageConditions()
	schema["description"] = fmt.Sprintf("All six root fields are required; checkpoint and governingAuthorityRefId are nullable. completedStageIds is an ordered prefix of the reviewed-change stage catalog. The checkpoint is null exactly for the complete prefix; otherwise its state selects an exact field set for the next stage, where not_started carries an incoming subject except at the first stage. Digest text may carry surrounding Unicode white space that native admission trims. Reference-ID lists are duplicate-free. Native admission additionally owns RuleID secret/timestamp exclusions, canonical safe repository-relative artifact paths with display-safe scalars and at most %d UTF-8 bytes each, strict refId ordering of contextRefs and strict ordering of every ID list, the %d-byte aggregate candidate path bound, resolution of dependencies, required refs, the governing authority (authority kind), the checkpoint subject (artifact kind with equal digest) and finding refs (finding kind), assessmentSubjectDigest equality, least-closure retention bounds and output byte caps. Any native refusal emits stderr without JSON. Admission does not authenticate caller context, digests or external state.", maxPathBytes, maxCandidatePathBytes)
	return schema
}

func checkpointStageConditions() []any {
	stages := workflowCatalog.Stages
	conditions := make([]any, 0, len(stages)+1)
	for index, stage := range stages {
		selectors := make([]any, 0, len(workflowCatalog.CheckpointActions))
		for _, definition := range workflowCatalog.CheckpointActions {
			fields := slices.Clone(checkpointFieldNames(definition, stage))
			slices.Sort(fields)
			selectors = append(selectors, map[string]any{
				"type": "object", "required": stringsValue(fields), "maxProperties": len(fields),
				"properties": map[string]any{"state": map[string]any{"const": definition.State}},
			})
		}
		conditions = append(conditions, map[string]any{
			"if":   stageCountCondition(index),
			"then": map[string]any{"properties": map[string]any{"checkpoint": map[string]any{"oneOf": selectors}}},
		})
	}
	return append(conditions, map[string]any{
		"if":   stageCountCondition(len(stages)),
		"then": map[string]any{"properties": map[string]any{"checkpoint": map[string]any{"type": "null"}}},
	})
}

func stageCountCondition(count int) map[string]any {
	return map[string]any{
		"required":   []any{"completedStageIds"},
		"properties": map[string]any{"completedStageIds": map[string]any{"minItems": count, "maxItems": count}},
	}
}

// refineWorkflowStructure applies two refinements that jsonshape cannot
// declare: stage lists become catalog prefixes, and every reference-ID list is
// duplicate-free because native admission and closure keep IDs strictly sorted.
func refineWorkflowStructure(schema map[string]any) map[string]any {
	stageItems := nestedSchema(jsonshape.Enum(setOf(workflowStageIDs()...)))
	referenceItems := nestedSchema(workflowRefIDShape())
	prefix := make([]any, len(workflowCatalog.Stages))
	for index, id := range workflowStageIDs() {
		prefix[index] = map[string]any{"type": "string", "const": id}
	}
	var visit func(any)
	visit = func(raw any) {
		switch value := raw.(type) {
		case map[string]any:
			if value["type"] == "array" && reflect.DeepEqual(value["items"], referenceItems) {
				value["uniqueItems"] = true
			}
			if value["type"] == "array" && reflect.DeepEqual(value["items"], stageItems) {
				maximum := schemaCount(value["maxItems"])
				value["prefixItems"] = slices.Clone(prefix[:maximum])
				value["items"] = false
			}
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(schema)
	return schema
}

func nestedSchema(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}

func schemaCount(raw any) int {
	switch value := raw.(type) {
	case int:
		return value
	case interface{ Int64() (int64, error) }:
		count, err := value.Int64()
		if err != nil {
			panic("invalid structural array bound")
		}
		return int(count)
	default:
		panic("structural stage list requires an explicit maximum")
	}
}

func setOf(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func literalTupleShape(values []string) jsonshape.Shape {
	items := make([]jsonshape.Shape, len(values))
	for index, value := range values {
		items[index] = jsonshape.StringLiteral(value)
	}
	return jsonshape.Tuple(items...)
}
