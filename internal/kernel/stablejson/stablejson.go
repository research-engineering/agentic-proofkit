package stablejson

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

var jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

type Layout string

const (
	LayoutPretty  Layout = "pretty"
	LayoutCompact Layout = "compact"
)

func Marshal(value any) ([]byte, error) {
	return MarshalLayout(value, LayoutPretty)
}

func MarshalLayout(value any, layout Layout) ([]byte, error) {
	if layout != LayoutPretty && layout != LayoutCompact {
		return nil, fmt.Errorf("unsupported JSON layout: %s", layout)
	}
	var builder strings.Builder
	if err := writeValue(&builder, value, 0, layout); err != nil {
		return nil, err
	}
	builder.WriteByte('\n')
	return []byte(builder.String()), nil
}

func writeValue(builder *strings.Builder, value any, depth int, layout Layout) error {
	switch typed := value.(type) {
	case nil:
		builder.WriteString("null")
	case bool:
		if typed {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
	case string:
		return writeQuotedString(builder, typed)
	case json.Number:
		if !isJSONNumberToken(typed.String()) {
			return fmt.Errorf("invalid JSON number: %s", typed.String())
		}
		builder.WriteString(typed.String())
	case int:
		builder.WriteString(strconv.Itoa(typed))
	case []any:
		return writeArray(builder, typed, depth, layout)
	case map[string]any:
		return writeObject(builder, typed, depth, layout)
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}

func isJSONNumberToken(value string) bool {
	return jsonNumberPattern.MatchString(value)
}

func writeArray(builder *strings.Builder, values []any, depth int, layout Layout) error {
	if len(values) == 0 {
		builder.WriteString("[]")
		return nil
	}
	builder.WriteByte('[')
	if layout == LayoutPretty {
		builder.WriteByte('\n')
	}
	for index, value := range values {
		if index > 0 {
			builder.WriteByte(',')
			if layout == LayoutPretty {
				builder.WriteByte('\n')
			}
		}
		if layout == LayoutPretty {
			writeIndent(builder, depth+1)
		}
		if err := writeValue(builder, value, depth+1, layout); err != nil {
			return err
		}
	}
	if layout == LayoutPretty {
		builder.WriteByte('\n')
		writeIndent(builder, depth)
	}
	builder.WriteByte(']')
	return nil
}

func writeObject(builder *strings.Builder, values map[string]any, depth int, layout Layout) error {
	if len(values) == 0 {
		builder.WriteString("{}")
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if !unicodepolicy.ValidScalarString(key) {
			return fmt.Errorf("stable JSON object key is not valid UTF-8")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	builder.WriteByte('{')
	if layout == LayoutPretty {
		builder.WriteByte('\n')
	}
	for index, key := range keys {
		if index > 0 {
			builder.WriteByte(',')
			if layout == LayoutPretty {
				builder.WriteByte('\n')
			}
		}
		if layout == LayoutPretty {
			writeIndent(builder, depth+1)
		}
		if err := writeQuotedString(builder, key); err != nil {
			return err
		}
		builder.WriteByte(':')
		if layout == LayoutPretty {
			builder.WriteByte(' ')
		}
		if err := writeValue(builder, values[key], depth+1, layout); err != nil {
			return err
		}
	}
	if layout == LayoutPretty {
		builder.WriteByte('\n')
		writeIndent(builder, depth)
	}
	builder.WriteByte('}')
	return nil
}

func writeIndent(builder *strings.Builder, depth int) {
	for i := 0; i < depth; i++ {
		builder.WriteString("  ")
	}
}

func writeQuotedString(builder *strings.Builder, value string) error {
	if !unicodepolicy.ValidScalarString(value) {
		return fmt.Errorf("stable JSON string is not valid UTF-8")
	}
	builder.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\t':
			builder.WriteString(`\t`)
		case '\n':
			builder.WriteString(`\n`)
		case '\f':
			builder.WriteString(`\f`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			if unicodepolicy.IsUnsafeScalar(character) {
				writeUnicodeEscape(builder, character)
			} else {
				builder.WriteRune(character)
			}
		}
	}
	builder.WriteByte('"')
	return nil
}

func writeUnicodeEscape(builder *strings.Builder, value rune) {
	if value <= 0xffff {
		_, _ = fmt.Fprintf(builder, `\u%04x`, value)
		return
	}
	high, low := utf16.EncodeRune(value)
	_, _ = fmt.Fprintf(builder, `\u%04x\u%04x`, high, low)
}
