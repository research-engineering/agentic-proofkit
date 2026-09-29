package compactproofcontract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// InputStructure describes raw compact rows, including their header-dependent
// cell types. Native normalization and semantic admission remain authoritative.
func InputStructure() map[string]any {
	space := trimSpacePatternClass()
	text := map[string]any{"type": "string", "pattern": "[^" + space + "]"}
	identifier := jsonshape.StringGrammar(admit.RuleIDPatternBody).JSONSchema()
	delete(identifier, "$schema")
	identifier["maxLength"] = admit.MaxRuleIDBytes
	normalizedIdentifier := map[string]any{"type": "string", "allOf": []any{
		map[string]any{"pattern": "^[" + space + "]*(?:" + admit.RuleIDPatternBody + ")[" + space + "]*(?![\\s\\S])"},
		map[string]any{"pattern": "^[" + space + "]*[^" + space + "]{1," + strconv.Itoa(admit.MaxRuleIDBytes) + "}[" + space + "]*(?![\\s\\S])"},
	}}
	texts := func(item map[string]any) map[string]any {
		return map[string]any{"type": "array", "items": item, "uniqueItems": true}
	}
	maximumOrder := maxJSONSafeInteger
	if strconv.IntSize == 32 {
		maximumOrder = 1<<31 - 1
	}
	order := map[string]any{"type": "integer", "minimum": json.Number("0"),
		"maximum": json.Number(strconv.FormatInt(maximumOrder, 10))}
	definitions := map[string]any{
		"text": text, "identifier": identifier, "normalizedIdentifier": normalizedIdentifier,
		"texts": texts(schemaReference("text")), "identifiers": texts(schemaReference("normalizedIdentifier")),
		"order": order, "witnessRow": rowStructure(len(witnessColumns)),
	}
	for _, columns := range [][]string{surfaceColumns[:], bindingColumns[:], witnessColumns[:]} {
		for _, name := range columns {
			definitions["column-"+name] = trimmedLiteralSchema(name, space)
		}
	}
	definitions["witnessColumn"] = map[string]any{"anyOf": []any{
		schemaReference("column-positive_witness"), schemaReference("column-falsification_witness"),
	}}
	columnShape := func(columns []string) map[string]any {
		contains := make([]any, 0, len(columns))
		for _, name := range columns {
			contains = append(contains, map[string]any{"contains": schemaReference("column-" + name)})
		}
		return map[string]any{"type": "array", "minItems": len(columns), "maxItems": len(columns), "allOf": contains}
	}
	properties := map[string]any{
		"authority_state":       trimmedLiteralSchema(AuthorityState, space),
		"binding_columns":       columnShape(bindingColumns[:]),
		"bindings":              map[string]any{"type": "array", "items": rowStructure(len(bindingColumns))},
		"contract_id":           schemaReference("text"),
		"contract_kind":         trimmedLiteralSchema(ContractKind, space),
		"non_claims":            schemaReference("texts"),
		"normalization_profile": trimmedLiteralSchema(NormalizationProfile, space),
		"schema_version":        map[string]any{"type": "integer", "const": json.Number("2")},
		"surface_columns":       columnShape(surfaceColumns[:]),
		"surfaces":              map[string]any{"type": "array", "items": rowStructure(len(surfaceColumns))},
		"witness_columns":       columnShape(witnessColumns[:]),
	}
	if len(properties) != len(inputKeys) {
		panic("compact structure differs from native root inventory")
	}
	required := make([]any, len(inputKeys))
	for i, key := range inputKeys {
		if _, exists := properties[key]; !exists {
			panic("compact structure omits native root member")
		}
		required[i] = key
	}
	surfaceCells := map[string]string{
		"surface_id": "identifier", "required_environment_classes": "identifiers",
		"preconditioned_environment_classes": "identifiers",
	}
	bindingCells := map[string]string{
		"requirement_id": "identifier", "surface_id": "identifier", "scenario_id": "text",
		"invariant_role": "identifier", "owned_invariant": "identifier", "blocking_status": "identifier",
		"required_environment_classes": "identifiers", "positive_witness": "witnessRow",
		"falsification_witness": "witnessRow", "verify_commands": "texts",
		"declared_mutation_resistance_claim_id": "identifier",
	}
	witnessCells := map[string]string{
		"selector": "text", "environment_classes": "identifiers",
		"verify_commands": "texts", "resolution_order_index": "order",
	}
	conditions := columnConditions("surface_columns", "surfaces", surfaceColumns[:], surfaceCells)
	conditions = append(conditions, columnConditions("binding_columns", "bindings", bindingColumns[:], bindingCells)...)
	// Two independently permutable headers determine each nested witness cell.
	for witnessPosition := range witnessColumns {
		for _, name := range witnessColumns {
			for bindingPosition := range bindingColumns {
				condition := map[string]any{"properties": map[string]any{
					"witness_columns": positionStructure(witnessPosition, schemaReference("column-"+name)),
					"binding_columns": positionStructure(bindingPosition, schemaReference("witnessColumn")),
				}}
				conditions = append(conditions, map[string]any{
					"if": condition,
					"then": map[string]any{"properties": map[string]any{"bindings": map[string]any{
						"items": positionStructure(bindingPosition, positionStructure(witnessPosition, schemaReference(witnessCells[name]))),
					}}},
				})
			}
		}
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     "urn:proofkit:compact-proof-declaration:schema:2", "$defs": definitions,
		"type": "object", "additionalProperties": false, "properties": properties, "required": required, "allOf": conditions,
		"description": "All members are required and non-null, without defaults. Headers are permutations of the exact owned names after Go strings.TrimSpace normalization; each cell is selected by its header name, including nested witness headers. Header cardinality plus one contains clause per disjoint name excludes unknown or repeated normalized columns. Empty surfaces, bindings, non-claims, environment lists and command lists are admitted. Native admission additionally enforces exact integer lexemes, secret-like and timestamp-like identifier rejection, normalized uniqueness, display-only command text, repo-relative witness selectors and scoped scenario identities. It checks unique surfaces and binding coordinates, surface references and hash-coordinate collision consistency, then sorts normalized records and lists. Structural schema validation does not normalize data, enforce these native-only policies, execute witnesses or prove caller evidence, freshness, authenticity or coverage. schema_version uses the literal integer token 2. resolution_order_index uses a canonical integer token, is nonnegative and fits both the JSON-safe and native-int domains; numeric fractions/exponents and negative zero are not interchangeable with canonical integer tokens.",
	}
}

func columnConditions(header, rows string, columns []string, cells map[string]string) []any {
	if len(cells) != len(columns) {
		panic("compact structure differs from native column inventory")
	}
	// Equal cell schemas share one condition; header names remain disjoint.
	groups := map[string][]any{}
	for _, name := range columns {
		cell, exists := cells[name]
		if !exists {
			panic("compact structure omits native column")
		}
		groups[cell] = append(groups[cell], schemaReference("column-"+name))
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]any, 0, len(columns)*len(groups))
	for position := range columns {
		for _, key := range keys {
			condition := map[string]any{"anyOf": groups[key]}
			result = append(result, map[string]any{
				"if":   map[string]any{"properties": map[string]any{header: positionStructure(position, condition)}},
				"then": map[string]any{"properties": map[string]any{rows: map[string]any{"items": positionStructure(position, schemaReference(key))}}},
			})
		}
	}
	return result
}

func schemaReference(name string) map[string]any {
	return map[string]any{"$ref": "#/$defs/" + name}
}

func rowStructure(width int) map[string]any {
	return map[string]any{"type": "array", "minItems": width, "maxItems": width}
}

func positionStructure(position int, cell any) map[string]any {
	prefix := make([]any, position+1)
	for i := range prefix {
		prefix[i] = true
	}
	prefix[position] = cell
	return map[string]any{"prefixItems": prefix}
}

func trimmedLiteralSchema(value, space string) map[string]any {
	return map[string]any{"type": "string", "pattern": "^[" + space + "]*" + regexp.QuoteMeta(value) + "[" + space + "]*(?![\\s\\S])"}
}

func trimSpacePatternClass() string {
	var result strings.Builder
	for _, row := range unicode.White_Space.R16 {
		for r := uint32(row.Lo); r <= uint32(row.Hi); r += uint32(row.Stride) {
			fmt.Fprintf(&result, `\u%04x`, r)
		}
	}
	if len(unicode.White_Space.R32) != 0 {
		panic("compact structural whitespace projection requires supplementary escape support")
	}
	return result.String()
}
