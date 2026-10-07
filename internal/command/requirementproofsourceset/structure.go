package requirementproofsourceset

import (
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func strictTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `](?:[\s\S]*[^` + space + `])?`
	})
}

func sourceIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func columnShape(columns []string) jsonshape.Shape {
	items := make([]jsonshape.Shape, len(columns))
	for i, name := range columns {
		items[i] = jsonshape.StringLiteral(name)
	}
	return jsonshape.Tuple(items...)
}

func InputStructure() map[string]any {
	text := strictTextShape()
	texts := jsonshape.Array(text, 1)
	envelope := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("contractKind", jsonshape.StringLiteral("requirement_proof_route_declaration_source")),
		jsonshape.Required("contractId", text),
		jsonshape.Required("authorityState", jsonshape.StringLiteral("caller_owned_requirement_proof_route_source")),
		jsonshape.Required("normalizationProfile", jsonshape.StringLiteral("json/v2:utf8+lf+declaration-row-arrays")),
		jsonshape.Required("nonClaims", texts),
		jsonshape.Required("surfaceColumns", columnShape(canonicalSurfaceColumns)),
		jsonshape.Required("bindingColumns", columnShape(canonicalBindingColumns)),
		jsonshape.Required("witnessColumns", columnShape(canonicalWitnessColumns)),
	)
	index := jsonshape.Object(
		jsonshape.Required("schema_version", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("contract_kind", jsonshape.StringLiteral("requirement_proof_route_declaration_source_set")),
		jsonshape.Required("contract_id", jsonshape.StringLiteral("requirement-proof-route-declarations/source-set/v2")),
		jsonshape.Required("authority_state", jsonshape.StringLiteral("caller_owned_requirement_proof_route_source_index")),
		jsonshape.Required("normalization_profile", jsonshape.StringLiteral("json/v2:utf8+lf+ordered-source-refs")),
		jsonshape.Required("non_claims", texts),
		jsonshape.Required("source_columns", columnShape(sourceSetColumns)),
		jsonshape.Required("sources", jsonshape.Array(jsonshape.Tuple(sourceIDShape(), text,
			jsonshape.StringGrammar(`[0-9a-f]{64}`), jsonshape.Enum(sourceRoles), texts), 1)),
	)
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("canonicalEnvelope", envelope), jsonshape.Required("sourceSet", index),
		jsonshape.Required("sources", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("path", text), jsonshape.Required("text", jsonshape.StringGrammar(`[\s\S]+`))), 0)),
		jsonshape.Optional("projection", jsonshape.Nullable(jsonshape.Object(
			jsonshape.Optional("kind", jsonshape.Nullable(jsonshape.Enum(projectionKinds))),
			jsonshape.Optional("selectedSourceIds", jsonshape.Nullable(jsonshape.Array(sourceIDShape(), 1))),
		))),
	).JSONSchema()
	schema["description"] = "Wire schemaVersion is the canonical integer token 2. Absent/null projection and absent/null kind select canonical_contract; absent/null selectedSourceIds select all indexed sources. Explicit IDs are nonempty and unique under native admission; selected sources retain index order, not selector order. Role and kind enums are exact raw strings. Envelope, index text and paths reject leading/trailing Go whitespace. Every supplied source text is a nonempty raw string, including unselected text; only selected text is parsed as strict JSON. Native admission owns repo-relative paths, source/path uniqueness, references, digest matching, selected payload/role agreement, fragment inflation and combined binding/resolver validity. Encoded source text is not an inline child contract. A structural pass neither performs these native checks nor proves witness execution or source authenticity."
	return schema
}

// Only source-owned headers differ. Table cell descriptions remain owned by
// compactproofcontract, and the new resource keeps its own local references.
func canonicalStructure() map[string]any {
	schema := compactproofcontract.InputStructure()
	schema["$id"] = "urn:proofkit:requirement-proof-source:canonical:schema:2"
	properties := schema["properties"].(map[string]any)
	for key, value := range map[string]string{
		"authority_state":       "caller_owned_requirement_proof_route_source",
		"contract_kind":         "requirement_proof_route_declaration_source",
		"normalization_profile": "json/v2:utf8+lf+declaration-row-arrays",
	} {
		properties[key] = jsonshape.StringLiteral(value).JSONSchema()
	}
	properties["contract_id"] = strictTextShape().JSONSchema()
	properties["non_claims"] = jsonshape.Array(strictTextShape(), 1).JSONSchema()
	properties["surface_columns"] = columnShape(canonicalSurfaceColumns).JSONSchema()
	properties["binding_columns"] = columnShape(canonicalBindingColumns).JSONSchema()
	properties["witness_columns"] = columnShape(canonicalWitnessColumns).JSONSchema()
	schema["description"] = "Source-owned strict headers and exact column order with compact-owner table cells. Native admission owns envelope agreement, combined references, source selection and normalization. A canonical source remains caller-owned declaration data, not execution evidence."
	return schema
}

func outputStructure(kind, field string, child map[string]any) map[string]any {
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("projectionKind", jsonshape.StringLiteral("proofkit.requirement-proof-source-set."+kind)),
		jsonshape.Required("inputPaths", jsonshape.Array(strictTextShape(), 1)),
		jsonshape.Required("selectedSourceIds", jsonshape.Array(sourceIDShape(), 1)),
		jsonshape.Required("sourceCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("sourceSetCount", jsonshape.IntegerMinimum(1)),
	).JSONSchema()
	schema["properties"].(map[string]any)[field] = child
	required := append(schema["required"].([]any), field)
	slices.SortFunc(required, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	schema["required"] = required
	schema["description"] = "Only successful source admission emits this projection; input errors emit no JSON. inputPaths is sorted unique, selectedSourceIds follows index order, sourceCount equals selected sources and sourceSetCount counts the entire index. The child contract is derived from selected payloads, preserving caller-owned declaration authority. Standard structure validation does not prove joins, count equality, digests, witness execution, freshness or authenticity."
	return schema
}

func CanonicalOutputStructure() map[string]any {
	return outputStructure("canonical_contract", "contract", canonicalStructure())
}

func ResolverOutputStructure() map[string]any {
	return outputStructure("resolver_input", "resolverInput", compactproofcontract.InputStructure())
}
