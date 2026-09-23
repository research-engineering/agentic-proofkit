package requirementsourcecodec

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// InputStructure describes structural admission only. Raw framing, aggregate
// resources, canonical normalization and semantics retain their native owners.
func InputStructure(limits requirementsourcemodel.Limits) (map[string]any, error) {
	shape, err := InputShape(limits)
	if err != nil {
		return nil, err
	}
	return shape.JSONSchema(), nil
}

// InputShape projects the same descriptor used by byte-coordinate admission.
// Its immutable children support owner-defined output projections, not source
// authenticity or a replacement for the codec's raw diagnostic boundary.
func InputShape(limits requirementsourcemodel.Limits) (jsonshape.Shape, error) {
	if err := requirementsourcemodel.ValidateLimits(limits); err != nil {
		return jsonshape.Shape{}, err
	}
	return sourceValueShape(documentShape(limits))
}

func sourceValueShape(expected *shape) (jsonshape.Shape, error) {
	if expected == nil {
		return jsonshape.Shape{}, fmt.Errorf("missing source shape declaration")
	}
	var value jsonshape.Shape
	switch expected.kind {
	case shapeObject:
		if expected.dynamic != nil {
			if expected.dynamic.kind != shapeString || expected.dynamic.nullable || expected.dynamic.exactString != "" || expected.maxItems <= 0 {
				return jsonshape.Shape{}, fmt.Errorf("unsupported dynamic source shape declaration")
			}
			value = jsonshape.StringMap(expected.maxItems)
			break
		}
		if expected.maxItems != 0 {
			return jsonshape.Shape{}, fmt.Errorf("unsupported closed-object source property bound")
		}
		fields := make([]jsonshape.Property, 0, len(expected.fields))
		for _, key := range sortedShapeFieldKeys(expected.fields) {
			field := expected.fields[key]
			child, err := sourceValueShape(field.shape)
			if err != nil {
				return jsonshape.Shape{}, err
			}
			if field.required {
				fields = append(fields, jsonshape.Required(key, child))
			} else {
				fields = append(fields, jsonshape.Optional(key, child))
			}
		}
		value = jsonshape.Object(fields...)
	case shapeArray:
		child, err := sourceValueShape(expected.element)
		if err != nil {
			return jsonshape.Shape{}, err
		}
		if expected.maxItems < 0 {
			return jsonshape.Shape{}, fmt.Errorf("invalid source array bound")
		}
		value = jsonshape.BoundedArray(child, 0, expected.maxItems)
	case shapeString:
		value = jsonshape.String()
		if expected.exactString != "" {
			value = jsonshape.StringLiteral(expected.exactString)
		}
	case shapeInteger:
		if expected.exactInt == nil {
			return jsonshape.Shape{}, fmt.Errorf("unsupported unconstrained source integer declaration")
		}
		value = jsonshape.IntegerLiteral(*expected.exactInt)
	case shapeDecimalInteger:
		value = jsonshape.DecimalIntegerString()
	case shapeBoolean:
		value = jsonshape.Boolean()
	default:
		return jsonshape.Shape{}, fmt.Errorf("unsupported source shape kind")
	}
	if expected.nullable {
		value = jsonshape.Nullable(value)
	}
	return value, nil
}
