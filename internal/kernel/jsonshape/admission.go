package jsonshape

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type violation struct {
	message string
	path    []string
}

type admissionMode uint8

const (
	callerSnapshot admissionMode = iota
	generatedValueCheck
)

func invalid(message string) *violation { return &violation{message: message} }

func (v *violation) at(segment string) *violation {
	v.path = append(v.path, segment)
	return v
}

// Admit returns a detached structural snapshot, preserving absent keys and null.
// Raw framing is admitted separately. Callers must not mutate input during the
// call. It never inserts defaults or performs semantic evaluation.
func (shape Shape) Admit(raw any, context string) (any, error) {
	result, failure := shape.admit(raw, callerSnapshot)
	return result, failure.contextual(context)
}

// CheckGenerated validates an owner-built projection without copying it.
// Only this path additionally accepts Go int as a canonical numeric carrier;
// it does not admit caller input or normalize the emitted value.
func (shape Shape) CheckGenerated(raw any, context string) error {
	_, failure := shape.admit(raw, generatedValueCheck)
	return failure.contextual(context)
}

func (failure *violation) contextual(context string) error {
	if failure == nil {
		return nil
	}
	var path strings.Builder
	path.WriteString(context)
	for i := len(failure.path) - 1; i >= 0; i-- {
		path.WriteString(failure.path[i])
	}
	return fmt.Errorf("%s %s", path.String(), failure.message)
}

// Successful traversal does not build diagnostic paths or copy declaration keys.
func (shape Shape) admit(raw any, mode admissionMode) (any, *violation) {
	n := shape.node
	if n == nil {
		return nil, invalid("has an invalid JSON shape declaration")
	}
	if raw == nil && n.nullable {
		return nil, nil
	}
	if mode == generatedValueCheck {
		if value, ok := raw.(int); ok {
			raw = json.Number(strconv.Itoa(value))
		}
	}
	switch n.kind {
	case nullKind:
		if raw != nil {
			return nil, invalid("must be null")
		}
		return nil, nil
	case oneOfKind:
		if n.discriminator != "" {
			record, ok := raw.(map[string]any)
			if !ok {
				return nil, invalid("must be an object")
			}
			tag, ok := record[n.discriminator].(string)
			branch, declared := n.branches[tag]
			if !ok || !declared {
				return nil, invalid("must be a declared discriminator value").at("." + n.discriminator)
			}
			return branch.admit(raw, mode)
		}
		var result any
		matches := 0
		for _, alternative := range n.alternatives {
			value, failure := alternative.admit(raw, mode)
			if failure == nil {
				result = value
				matches++
			}
		}
		if matches != 1 {
			return nil, invalid("must match exactly one structural alternative")
		}
		return result, nil
	case objectKind:
		return shape.admitObject(raw, mode)
	case stringMapKind:
		record, ok := raw.(map[string]any)
		if !ok {
			return nil, invalid("must be an object")
		}
		if len(record) > n.maxItems {
			return nil, invalid(fmt.Sprintf("must contain at most %d properties", n.maxItems))
		}
		var result map[string]any
		if mode == callerSnapshot {
			result = make(map[string]any, len(record))
		}
		for key, value := range record {
			if _, ok := value.(string); !ok {
				return nil, invalid("map values must be strings")
			}
			if mode == callerSnapshot {
				result[key] = value
			}
		}
		return result, nil
	case arrayKind, tupleKind:
		values, ok := raw.([]any)
		if !ok {
			return nil, invalid("must be an array")
		}
		if n.kind == tupleKind && len(values) != len(n.tuple) {
			return nil, invalid(fmt.Sprintf("must contain exactly %d items", len(n.tuple)))
		}
		if n.kind == arrayKind && n.maxItems >= 0 && len(values) > n.maxItems {
			return nil, invalid(fmt.Sprintf("must contain at most %d items", n.maxItems))
		}
		if n.kind == arrayKind && len(values) < n.minItems {
			if n.minItems == 1 {
				return nil, invalid("must be non-empty")
			}
			return nil, invalid(fmt.Sprintf("must contain at least %d items", n.minItems))
		}
		var result []any
		if mode == callerSnapshot {
			result = make([]any, len(values))
		}
		for i, value := range values {
			element := n.element
			if n.kind == tupleKind {
				element = n.tuple[i]
			}
			admitted, failure := element.admit(value, mode)
			if failure != nil {
				return nil, failure.at("[" + strconv.Itoa(i) + "]")
			}
			if mode == callerSnapshot {
				result[i] = admitted
			}
		}
		return result, nil
	case stringKind:
		value, ok := raw.(string)
		if !ok {
			return nil, invalid("must be a string")
		}
		if len(n.enum) != 0 && !slices.Contains(n.enum, value) {
			return nil, invalid("must be a declared enum value")
		}
		return raw, nil
	case numberKind:
		if _, ok := raw.(json.Number); !ok {
			return nil, invalid("must be a JSON number")
		}
		return raw, nil
	case integerLiteralKind:
		if !admit.JSONNumberEquals(raw, n.integer) {
			return nil, invalid(fmt.Sprintf("must be canonical integer %d", n.integer))
		}
		return raw, nil
	case integerMinimumKind:
		value, ok := raw.(json.Number)
		if !ok || len(value.String()) > 20 {
			return nil, invalid("must be a canonical JSON integer")
		}
		integer, err := admit.CanonicalInteger(value, "integer")
		if err != nil || integer < n.integer {
			return nil, invalid(fmt.Sprintf("must be a canonical int64 integer at least %d", n.integer))
		}
		return raw, nil
	case booleanKind:
		value, ok := raw.(bool)
		if !ok {
			return nil, invalid("must be a boolean")
		}
		if n.boolean != nil && value != *n.boolean {
			return nil, invalid("must be the declared boolean literal")
		}
		return raw, nil
	case stringLiteralKind:
		value, ok := raw.(string)
		if !ok || value != n.text {
			return nil, invalid("must be the declared text literal")
		}
		return raw, nil
	case stringSuffixKind:
		value, ok := raw.(string)
		if !ok || !strings.HasSuffix(value, n.text) {
			return nil, invalid("must have the declared text suffix")
		}
		return raw, nil
	case stringGrammarKind:
		value, ok := raw.(string)
		if !ok || !n.grammar.MatchString(value) {
			return nil, invalid("must match the declared text grammar")
		}
		return raw, nil
	case decimalIntegerKind:
		value, ok := raw.(string)
		if !ok || len(value) > 20 {
			return nil, invalid("must be canonical decimal int64 text")
		}
		if _, err := admit.CanonicalInteger(json.Number(value), "integer"); err != nil {
			return nil, invalid("must be canonical decimal int64 text")
		}
		return raw, nil
	default:
		return nil, invalid("has an invalid JSON shape kind")
	}
}

func (shape Shape) admitObject(raw any, mode admissionMode) (any, *violation) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, invalid("must be an object")
	}
	n := shape.node
	for key := range record {
		if _, known := n.allowed[key]; !known {
			return nil, invalid("contains an unsupported field")
		}
	}
	if len(n.exactlyOne) != 0 {
		present := 0
		for _, name := range n.exactlyOne {
			if _, exists := record[name]; exists {
				present++
			}
		}
		if present != 1 {
			return nil, invalid("must contain exactly one of the declared alternative fields")
		}
	}
	var result map[string]any
	if mode == callerSnapshot {
		result = make(map[string]any, len(record))
	}
	for _, field := range n.properties {
		value, exists := record[field.name]
		if !exists {
			if field.optional {
				continue
			}
			return nil, invalid("is required").at("." + field.name)
		}
		admitted, failure := field.shape.admit(value, mode)
		if failure != nil {
			return nil, failure.at("." + field.name)
		}
		if mode == callerSnapshot {
			result[field.name] = admitted
		}
	}
	return result, nil
}
