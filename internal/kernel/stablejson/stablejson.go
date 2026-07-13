package stablejson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
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
		builder.WriteString(quote(typed))
	case json.Number:
		if !isJSONNumberToken(typed.String()) {
			return fmt.Errorf("invalid JSON number: %s", typed.String())
		}
		builder.WriteString(typed.String())
	case int:
		builder.WriteString(fmt.Sprintf("%d", typed))
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
		builder.WriteString(quote(key))
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

func quote(value string) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(buffer.String(), "\n")
}
