package requirementsourcecodec

import (
	"encoding/json"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// AssessValue borrows an already decoded plain-JSON value until return.
// Its detached snapshot has no authority over original bytes or coordinates.
func AssessValue(value any) (requirementsourcemodel.Assessment, error) {
	return AssessValueWithLimits(value, DefaultLimits(), requirementsourcemodel.DefaultLimits())
}

func AssessValueWithLimits(value any, codecLimits Limits, modelLimits requirementsourcemodel.Limits) (requirementsourcemodel.Assessment, error) {
	if err := validateLimits(codecLimits, modelLimits); err != nil {
		return requirementsourcemodel.Assessment{}, err
	}
	encoder := valueEncoder{writer: canonicalWriter{maxBytes: codecLimits.MaxRawBytes}, maxDepth: codecLimits.MaxNesting}
	encoder.encode(value, documentShape(modelLimits), "", 1)
	if encoder.writer.err != nil {
		return requirementsourcemodel.Assessment{}, withoutCoordinates(encoder.writer.err)
	}
	source := encoder.writer.buffer.Bytes()
	decoded, err := decodeSource(source, codecLimits, modelLimits)
	if err != nil {
		return requirementsourcemodel.Assessment{}, withoutCoordinates(err)
	}
	assessment, err := requirementsourcemodel.AssessWithLimits(decoded.draft, modelLimits)
	if err != nil {
		return requirementsourcemodel.Assessment{}, withoutCoordinates(modelDiagnostic(source, decoded.locations, decoded.wire, err))
	}
	return assessment, nil
}

type valueEncoder struct {
	writer   canonicalWriter
	maxDepth int
}

// The closed grammar bounds recursive containers. No reflection, custom
// marshaling, caller accessors or second reads participate in serialization.
func (encoder *valueEncoder) encode(value any, expected *shape, path string, depth int) {
	if encoder.writer.err != nil {
		return
	}
	if depth > encoder.maxDepth {
		encoder.fail("nesting_limit_exceeded", path)
		return
	}
	switch typed := value.(type) {
	case nil:
		encoder.writer.writeString("null")
	case bool:
		encoder.writer.writeString(strconv.FormatBool(typed))
	case string:
		encoder.text(typed, path)
	case json.Number:
		if int64(len(typed)) > encoder.writer.maxBytes-int64(encoder.writer.buffer.Len()) {
			encoder.fail("raw_byte_limit_exceeded", path)
			return
		}
		if _, ok := parseCanonicalInt64(string(typed)); !ok {
			encoder.fail("invalid_integer", path)
			return
		}
		encoder.writer.writeString(string(typed))
	case []any:
		if expected == nil || expected.kind != shapeArray {
			encoder.fail("invalid_type", path)
			return
		}
		if len(typed) > expected.maxItems {
			encoder.fail("collection_limit_exceeded", path)
			return
		}
		encoder.writer.writeByte('[')
		for index, item := range typed {
			if encoder.writer.err != nil {
				return
			}
			if index > 0 {
				encoder.writer.writeByte(',')
			}
			encoder.encode(item, expected.element, joinPointer(path, strconv.Itoa(index)), depth+1)
		}
		encoder.writer.writeByte(']')
	case map[string]any:
		encoder.object(typed, expected, path, depth)
	default:
		encoder.fail("invalid_type", path)
	}
}

func (encoder *valueEncoder) object(value map[string]any, expected *shape, path string, depth int) {
	if expected == nil || expected.kind != shapeObject {
		encoder.fail("invalid_type", path)
		return
	}
	limit := len(expected.fields)
	if expected.dynamic != nil {
		limit = expected.maxItems
	}
	if len(value) > limit {
		encoder.fail("collection_limit_exceeded", path)
		return
	}
	keys := make([]string, 0, len(value))
	remaining := encoder.writer.maxBytes - int64(encoder.writer.buffer.Len())
	for key := range value {
		if int64(len(key)) > remaining {
			encoder.fail("raw_byte_limit_exceeded", path)
			return
		}
		remaining -= int64(len(key))
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoder.writer.writeByte('{')
	for index, key := range keys {
		if encoder.writer.err != nil {
			return
		}
		safeKey, child := safeObjectChild(expected, key)
		childPath := joinPointer(path, safeKey)
		if child == nil {
			encoder.fail("unknown_field", childPath)
			return
		}
		if index > 0 {
			encoder.writer.writeByte(',')
		}
		encoder.text(key, childPath)
		encoder.writer.writeByte(':')
		encoder.encode(value[key], child, childPath, depth+1)
	}
	encoder.writer.writeByte('}')
}

func (encoder *valueEncoder) text(value, path string) {
	if int64(len(value)) > encoder.writer.maxBytes-int64(encoder.writer.buffer.Len()) {
		encoder.fail("raw_byte_limit_exceeded", path)
		return
	}
	if !utf8.ValidString(value) {
		encoder.fail("invalid_utf8", path)
		return
	}
	encoder.writer.writeJSONString(value)
}

func (encoder *valueEncoder) fail(code, path string) {
	encoder.writer.err = &Error{diagnostic: Diagnostic{Code: code, Path: path, CoordinateState: "unavailable"}}
}

func withoutCoordinates(err error) error {
	if typed, ok := err.(*Error); ok {
		return &Error{diagnostic: Diagnostic{Code: typed.diagnostic.Code, Path: typed.diagnostic.Path, CoordinateState: "unavailable"}}
	}
	return err
}
