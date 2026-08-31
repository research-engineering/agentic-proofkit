package jsonpointer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

// Pointer is an admitted RFC 6901 pointer. Its tokens are immutable outside
// this package, so syntax admission can precede input I/O without reparsing.
type Pointer struct {
	tokens []string
}

// Parse admits pointer syntax without consulting a JSON document.
func Parse(value string) (Pointer, error) {
	if !unicodepolicy.ValidScalarString(value) {
		return Pointer{}, fmt.Errorf("JSON pointer must be valid UTF-8")
	}
	if value == "" {
		return Pointer{}, nil
	}
	if !strings.HasPrefix(value, "/") {
		return Pointer{}, fmt.Errorf("JSON pointer must be an RFC 6901 pointer")
	}
	tokens := make([]string, 0, strings.Count(value, "/"))
	for _, rawPart := range strings.Split(value[1:], "/") {
		part, err := decodePointerToken(rawPart)
		if err != nil {
			return Pointer{}, err
		}
		tokens = append(tokens, part)
	}
	return Pointer{tokens: tokens}, nil
}

func Select(input any, pointer string) (any, error) {
	parsed, err := Parse(pointer)
	if err != nil {
		return nil, err
	}
	return SelectParsed(input, parsed)
}

// SelectParsed resolves an already-admitted pointer against input.
func SelectParsed(input any, pointer Pointer) (any, error) {
	current := input
	for position, part := range pointer.tokens {
		switch typed := current.(type) {
		case []any:
			index, err := arrayIndex(part)
			if err != nil {
				return nil, err
			}
			if index >= len(typed) {
				return nil, fmt.Errorf("JSON pointer segment %d does not exist: %s", position, diagnosticToken(part))
			}
			current = typed[index]
		case map[string]any:
			value, ok := typed[part]
			if !ok {
				return nil, fmt.Errorf("JSON pointer segment %d does not exist: %s", position, diagnosticToken(part))
			}
			current = value
		default:
			return nil, fmt.Errorf("JSON pointer segment %d does not exist: %s", position, diagnosticToken(part))
		}
	}
	return current, nil
}

func decodePointerToken(raw string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(raw))
	for index := 0; index < len(raw); index++ {
		char := raw[index]
		if char != '~' {
			builder.WriteByte(char)
			continue
		}
		if index+1 >= len(raw) {
			return "", fmt.Errorf("JSON pointer token contains invalid escape: %s", diagnosticToken(raw))
		}
		switch raw[index+1] {
		case '0':
			builder.WriteByte('~')
		case '1':
			builder.WriteByte('/')
		default:
			return "", fmt.Errorf("JSON pointer token contains invalid escape: %s", diagnosticToken(raw))
		}
		index++
	}
	return builder.String(), nil
}

func arrayIndex(part string) (int, error) {
	if part == "" {
		return 0, fmt.Errorf("JSON pointer array segment must be an index: %s", diagnosticToken(part))
	}
	if len(part) > 1 && part[0] == '0' {
		return 0, fmt.Errorf("JSON pointer array segment must be an index: %s", diagnosticToken(part))
	}
	for _, char := range part {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("JSON pointer array segment must be an index: %s", diagnosticToken(part))
		}
	}
	value, err := strconv.Atoi(part)
	if err != nil {
		return 0, fmt.Errorf("JSON pointer array segment must be an index: %s", diagnosticToken(part))
	}
	return value, nil
}

func diagnosticToken(value string) string {
	return admit.RedactDiagnosticValue(value)
}
