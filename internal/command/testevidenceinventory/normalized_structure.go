package testevidenceinventory

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// NormalizedInputStructure preserves the receiving domain, including wrapped
// direct inventories and absent or null projection markers. Joins stay native.
func NormalizedInputStructure() map[string]any {
	fields := normalizedFields(DirectBoundaryShape())
	fields = append(fields,
		jsonshape.Optional("projectionKind", jsonshape.Nullable(jsonshape.StringLiteral(ProofBindingProjectionKind))),
		jsonshape.Optional("projectionSummary", jsonshape.Nullable(projectionSummaryShape())))
	schema := jsonshape.Object(fields...).JSONSchema()
	ruleID := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).JSONSchema()
	derivedID := normalizedProducedIDShape().JSONSchema()
	schema["properties"].(map[string]any)["normalizedInventoryId"] = map[string]any{"anyOf": []any{ruleID, derivedID}}
	schema["oneOf"] = []any{
		map[string]any{"properties": map[string]any{"projectionKind": map[string]any{"type": "null"}, "projectionSummary": map[string]any{"type": "null"}}},
		map[string]any{"required": []any{"projectionKind", "projectionSummary"}, "properties": map[string]any{
			"projectionKind": map[string]any{"type": "string"}, "projectionSummary": map[string]any{"type": "object"},
		}},
	}
	return schema
}

func NormalizedOutputStructure() map[string]any {
	return jsonshape.Object(normalizedFields(CanonicalInventoryShape())...).JSONSchema()
}

// NormalizedProjectionStructure describes re-admission's canonical envelope.
// Unlike a newly produced inventory, its ID may be any admitted receiving ID.
func NormalizedProjectionStructure() map[string]any {
	schema := NormalizedInputStructure()
	properties := schema["properties"].(map[string]any)
	properties["inventory"] = CanonicalInventoryShape().JSONSchema()
	properties["projectionKind"] = jsonshape.StringLiteral(ProofBindingProjectionKind).JSONSchema()
	properties["projectionSummary"] = projectionSummaryShape().JSONSchema()
	return schema
}

func ProofBindingNormalizedOutputStructure() map[string]any {
	fields := normalizedFields(CanonicalInventoryShape())
	fields = append(fields, jsonshape.Required("projectionKind", jsonshape.StringLiteral(ProofBindingProjectionKind)),
		jsonshape.Required("projectionSummary", projectionSummaryShape()))
	return jsonshape.Object(fields...).JSONSchema()
}

func normalizedFields(inventory jsonshape.Shape) []jsonshape.Property {
	text := jsonshape.String()
	columns := make([]jsonshape.Shape, len(sourceSetColumns))
	for i, name := range sourceSetColumns {
		columns[i] = jsonshape.StringLiteral(name)
	}
	return []jsonshape.Property{
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("normalizedKind", jsonshape.StringLiteral(NormalizedInventoryKind)),
		jsonshape.Required("normalizedInventoryId", normalizedProducedIDShape()),
		jsonshape.Required("sourceAuthority", jsonshape.Enum(map[string]struct{}{directAuthority: {}, sourceSetAuthority: {}})),
		jsonshape.Required("sourceCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("sourceColumns", jsonshape.Tuple(columns...)),
		jsonshape.Required("sources", jsonshape.Array(sourceRowShape(), 0)),
		jsonshape.Required("entrySources", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("path", text), jsonshape.Required("sourceId", text), jsonshape.Required("testId", text),
		), 0)),
		jsonshape.Required("inputPaths", jsonshape.Array(text, 0)),
		jsonshape.Required("inventory", inventory),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
	}
}

func normalizedProducedIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody+regexp.QuoteMeta(normalizedInventoryIDSuffix), admit.MaxRuleIDBytes+len(normalizedInventoryIDSuffix))
}

func projectionSummaryShape() jsonshape.Shape {
	text := jsonshape.String()
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("entryCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("commandRefCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("routeEntryMappings", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("bindingRecordId", text), jsonshape.Required("requirementId", text),
			jsonshape.Required("resolutionOrderIndex", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("role", jsonshape.StringLiteral(compactproofcontract.FalsificationWitnessRole)),
			jsonshape.Required("scenarioId", text), jsonshape.Required("selector", text),
			jsonshape.Required("surfaceId", text), jsonshape.Required("testId", text), jsonshape.Required("witnessRouteId", text),
		), 0)),
	)
}
