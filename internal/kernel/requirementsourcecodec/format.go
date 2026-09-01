package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

var rawMessageType = reflect.TypeOf(json.RawMessage{})

type objectEntry struct {
	key   string
	value reflect.Value
}

type canonicalWriter struct {
	buffer bytes.Buffer
	err    error
}

func Format(model requirementsourcemodel.Model) ([]byte, error) {
	return FormatWithLimits(model, DefaultLimits(), requirementsourcemodel.DefaultLimits())
}

func FormatWithLimits(model requirementsourcemodel.Model, codecLimits Limits, modelLimits requirementsourcemodel.Limits) ([]byte, error) {
	if err := validateLimits(codecLimits, modelLimits); err != nil {
		return nil, err
	}
	wire, err := documentFromModel(model)
	if err != nil {
		return nil, formatError("invalid_model_projection")
	}
	draft, err := draftFromDocument(wire)
	if err != nil {
		return nil, formatError("invalid_model_projection")
	}
	readmitted, err := requirementsourcemodel.NormalizeWithLimits(draft, modelLimits)
	if err != nil || !sameModel(model, readmitted) {
		return nil, formatError("invalid_model")
	}
	writer := &canonicalWriter{}
	writer.writeHybrid(reflect.ValueOf(wire), 0, true, true)
	writer.writeByte('\n')
	if writer.err != nil {
		return nil, writer.err
	}
	if int64(writer.buffer.Len()) > codecLimits.MaxOutputBytes {
		return nil, formatError("canonical_output_limit_exceeded")
	}
	return append([]byte(nil), writer.buffer.Bytes()...), nil
}

func sameModel(left requirementsourcemodel.Model, right requirementsourcemodel.Model) bool {
	return reflect.DeepEqual(left.Atomic(), right.Atomic()) &&
		reflect.DeepEqual(left.Layout(), right.Layout()) &&
		reflect.DeepEqual(left.References(), right.References())
}

func (writer *canonicalWriter) writeHybrid(value reflect.Value, depth int, forceObjectMultiline bool, leadingIndent bool) {
	if writer.err != nil {
		return
	}
	value = indirectValue(value)
	if !value.IsValid() {
		if leadingIndent {
			writer.writeIndent(depth)
		}
		writer.writeString("null")
		return
	}
	if value.Type() == rawMessageType {
		if leadingIndent {
			writer.writeIndent(depth)
		}
		writer.writeRawMessage(value.Bytes())
		return
	}
	switch value.Kind() {
	case reflect.Slice, reflect.Array:
		if !arrayContainsObject(value) {
			if leadingIndent {
				writer.writeIndent(depth)
			}
			writer.writeCompact(value)
			return
		}
		if leadingIndent {
			writer.writeIndent(depth)
		}
		writer.writeByte('[')
		for index := 0; index < value.Len(); index++ {
			writer.writeByte('\n')
			if index == 0 {
				writer.writeHybrid(value.Index(index), depth+1, false, true)
			} else {
				writer.writeIndent(depth)
				writer.writeString(", ")
				writer.writeHybrid(value.Index(index), depth+1, false, false)
			}
		}
		writer.writeByte('\n')
		writer.writeIndent(depth)
		writer.writeByte(']')
	case reflect.Struct, reflect.Map:
		entries := objectEntries(value)
		if !forceObjectMultiline && !hasObjectArray(entries) {
			if leadingIndent {
				writer.writeIndent(depth)
			}
			writer.writeCompact(value)
			return
		}
		if leadingIndent {
			writer.writeIndent(depth)
		}
		writer.writeByte('{')
		for index, entry := range entries {
			writer.writeByte('\n')
			writer.writeIndent(depth + 1)
			writer.writeJSONString(entry.key)
			writer.writeString(": ")
			if arrayContainsObject(entry.value) {
				writer.writeHybrid(entry.value, depth+1, false, false)
			} else {
				writer.writeCompact(entry.value)
			}
			if index+1 < len(entries) {
				writer.writeByte(',')
			}
		}
		writer.writeByte('\n')
		writer.writeIndent(depth)
		writer.writeByte('}')
	default:
		if leadingIndent {
			writer.writeIndent(depth)
		}
		writer.writeCompact(value)
	}
}

func (writer *canonicalWriter) writeCompact(value reflect.Value) {
	if writer.err != nil {
		return
	}
	value = indirectValue(value)
	if !value.IsValid() {
		writer.writeString("null")
		return
	}
	if value.Type() == rawMessageType {
		writer.writeRawMessage(value.Bytes())
		return
	}
	switch value.Kind() {
	case reflect.String:
		writer.writeJSONString(value.String())
	case reflect.Bool:
		writer.writeString(strconv.FormatBool(value.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		writer.writeString(strconv.FormatInt(value.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		writer.writeString(strconv.FormatUint(value.Uint(), 10))
	case reflect.Slice, reflect.Array:
		writer.writeByte('[')
		for index := 0; index < value.Len(); index++ {
			if index > 0 {
				writer.writeByte(',')
			}
			writer.writeCompact(value.Index(index))
		}
		writer.writeByte(']')
	case reflect.Struct, reflect.Map:
		writer.writeByte('{')
		entries := objectEntries(value)
		for index, entry := range entries {
			if index > 0 {
				writer.writeByte(',')
			}
			writer.writeJSONString(entry.key)
			writer.writeByte(':')
			writer.writeCompact(entry.value)
		}
		writer.writeByte('}')
	default:
		writer.err = formatError("unsupported_model_value")
	}
}

func (writer *canonicalWriter) writeRawMessage(payload []byte) {
	if bytes.Equal(payload, []byte("null")) {
		writer.writeString("null")
		return
	}
	var value deferral
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&value); err != nil {
		writer.err = formatError("invalid_model_projection")
		return
	}
	writer.writeCompact(reflect.ValueOf(value))
}

func (writer *canonicalWriter) writeJSONString(value string) {
	if !utf8.ValidString(value) {
		writer.err = formatError("invalid_model_text")
		return
	}
	writer.writeByte('"')
	for _, character := range value {
		switch character {
		case '"':
			writer.writeString(`\"`)
		case '\\':
			writer.writeString(`\\`)
		case '\b':
			writer.writeString(`\b`)
		case '\f':
			writer.writeString(`\f`)
		case '\n':
			writer.writeString(`\n`)
		case '\r':
			writer.writeString(`\r`)
		case '\t':
			writer.writeString(`\t`)
		default:
			if unicodepolicy.IsUnsafeScalar(character) {
				writer.writeUnicodeEscape(character)
			} else {
				writer.writeString(string(character))
			}
		}
	}
	writer.writeByte('"')
}

func (writer *canonicalWriter) writeUnicodeEscape(character rune) {
	if character <= 0xffff {
		writer.writeString(`\u`)
		writer.writeString(lowerHex4(uint16(character)))
		return
	}
	high, low := utf16.EncodeRune(character)
	writer.writeString(`\u`)
	writer.writeString(lowerHex4(uint16(high)))
	writer.writeString(`\u`)
	writer.writeString(lowerHex4(uint16(low)))
}

func lowerHex4(value uint16) string {
	const digits = "0123456789abcdef"
	buffer := [4]byte{}
	for index := len(buffer) - 1; index >= 0; index-- {
		buffer[index] = digits[value&0xf]
		value >>= 4
	}
	return string(buffer[:])
}

func (writer *canonicalWriter) writeIndent(depth int) {
	writer.writeString(strings.Repeat("  ", depth))
}

func (writer *canonicalWriter) writeString(value string) {
	if writer.err == nil {
		_, _ = writer.buffer.WriteString(value)
	}
}

func (writer *canonicalWriter) writeByte(value byte) {
	if writer.err == nil {
		_ = writer.buffer.WriteByte(value)
	}
}

func indirectValue(value reflect.Value) reflect.Value {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func arrayContainsObject(value reflect.Value) bool {
	value = indirectValue(value)
	if !value.IsValid() || (value.Kind() != reflect.Slice && value.Kind() != reflect.Array) {
		return false
	}
	for index := 0; index < value.Len(); index++ {
		item := indirectValue(value.Index(index))
		if item.IsValid() && (item.Kind() == reflect.Struct || item.Kind() == reflect.Map) {
			return true
		}
	}
	return false
}

func hasObjectArray(entries []objectEntry) bool {
	for _, entry := range entries {
		if arrayContainsObject(entry.value) {
			return true
		}
	}
	return false
}

func objectEntries(value reflect.Value) []objectEntry {
	value = indirectValue(value)
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Map {
		keys := value.MapKeys()
		sort.Slice(keys, func(left, right int) bool { return keys[left].String() < keys[right].String() })
		result := make([]objectEntry, 0, len(keys))
		for _, key := range keys {
			result = append(result, objectEntry{key: key.String(), value: value.MapIndex(key)})
		}
		return result
	}
	result := make([]objectEntry, 0, value.NumField())
	typeValue := value.Type()
	for index := 0; index < value.NumField(); index++ {
		fieldType := typeValue.Field(index)
		if fieldType.PkgPath != "" {
			continue
		}
		name, options := parseJSONTag(fieldType.Tag.Get("json"))
		if name == "-" {
			continue
		}
		if name == "" {
			name = fieldType.Name
		}
		fieldValue := value.Field(index)
		if options["omitempty"] && fieldValue.IsZero() {
			continue
		}
		result = append(result, objectEntry{key: name, value: fieldValue})
	}
	return result
}

func parseJSONTag(tag string) (string, map[string]bool) {
	parts := strings.Split(tag, ",")
	options := make(map[string]bool, len(parts)-1)
	for _, option := range parts[1:] {
		options[option] = true
	}
	return parts[0], options
}

func formatError(code string) error {
	return &Error{diagnostic: Diagnostic{Code: code, CoordinateState: "byte_only"}}
}
