package jsonshape

import (
	"encoding/json"
	"regexp"
	"strconv"
)

// JSONSchema returns a detached draft 2020-12 structural projection as a
// recursive map[string]any/[]any/scalar value tree, not custom JSON marshalers.
// It does not claim raw framing, canonical scalar policies or semantic evaluation.
func (shape Shape) JSONSchema() map[string]any {
	value := shape.schemaValue()
	value["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	return value
}

func (shape Shape) schemaValue() map[string]any {
	n := shape.node
	if n == nil {
		panic("invalid JSON shape declaration")
	}
	value := map[string]any{}
	switch n.kind {
	case nullKind:
		value["type"] = "null"
	case oneOfKind:
		alternatives := make([]any, len(n.alternatives))
		for i, shape := range n.alternatives {
			alternatives[i] = shape.schemaValue()
		}
		value["oneOf"] = alternatives
	case objectKind:
		value["type"] = "object"
		value["additionalProperties"] = false
		properties := make(map[string]any, len(n.properties))
		required := []any{}
		for _, field := range n.properties {
			properties[field.name] = field.shape.schemaValue()
			if !field.optional {
				required = append(required, field.name)
			}
		}
		value["properties"] = properties
		if len(required) > 0 {
			value["required"] = required
		}
		if len(n.exactlyOne) > 0 {
			alternatives := make([]any, len(n.exactlyOne))
			for i, key := range n.exactlyOne {
				alternatives[i] = map[string]any{"required": []any{key}}
			}
			value["oneOf"] = alternatives
		}
	case arrayKind:
		value["type"] = "array"
		value["items"] = n.element.schemaValue()
		if n.minItems > 0 {
			value["minItems"] = n.minItems
		}
		if n.maxItems >= 0 {
			value["maxItems"] = json.Number(strconv.Itoa(n.maxItems))
		}
	case stringMapKind:
		value["type"] = "object"
		value["additionalProperties"] = map[string]any{"type": "string"}
		value["maxProperties"] = json.Number(strconv.Itoa(n.maxItems))
	case tupleKind:
		value["type"], value["items"] = "array", false
		value["minItems"], value["maxItems"] = len(n.tuple), len(n.tuple)
		if len(n.tuple) > 0 {
			items := make([]any, len(n.tuple))
			for i, shape := range n.tuple {
				items[i] = shape.schemaValue()
			}
			value["prefixItems"] = items
		}
	case stringKind:
		value["type"] = "string"
		if len(n.enum) > 0 {
			items := make([]any, len(n.enum))
			for i, item := range n.enum {
				items[i] = item
			}
			value["enum"] = items
		}
	case numberKind:
		value["type"] = "number"
	case booleanKind:
		value["type"] = "boolean"
		if n.boolean != nil {
			value["const"] = *n.boolean
		}
	case stringLiteralKind:
		value["type"], value["const"] = "string", n.text
	case stringSuffixKind:
		value["type"], value["pattern"] = "string", regexp.QuoteMeta(n.text)+`(?![\s\S])`
	case stringGrammarKind:
		value["type"], value["pattern"] = "string", "^(?:"+n.text+`)(?![\s\S])`
	case decimalIntegerKind:
		value["type"], value["x-proofkit-number-encoding"] = "string", "decimal-int64"
	case integerLiteralKind:
		value["type"] = "integer"
		value["const"] = json.Number(strconv.FormatInt(n.integer, 10))
		value["x-proofkit-number-encoding"] = "canonical-int64"
	case integerMinimumKind:
		value["type"] = "integer"
		value["minimum"] = json.Number(strconv.FormatInt(n.integer, 10))
		value["maximum"] = json.Number("9223372036854775807")
		value["x-proofkit-number-encoding"] = "canonical-int64"
	default:
		panic("invalid JSON shape kind")
	}
	if n.nullable {
		return map[string]any{"anyOf": []any{map[string]any{"type": "null"}, value}}
	}
	return value
}
