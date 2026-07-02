package jsonpointer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func Select(input any, pointer string) (any, error) {
	if pointer == "" {
		return input, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("JSON pointer must be an RFC 6901 pointer")
	}
	current := input
	for position, rawPart := range strings.Split(pointer[1:], "/") {
		part, err := decodePointerToken(rawPart)
		if err != nil {
			return nil, err
		}
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
