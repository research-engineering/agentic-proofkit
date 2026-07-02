package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
)

func DecodeJSON(reader io.Reader, maxBytes int64) (any, error) {
	source, err := readBounded(reader, maxBytes)
	if err != nil {
		return nil, err
	}
	if err := assertUniqueObjectKeys(source); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid JSON input: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("invalid JSON input: multiple JSON values")
	}
	return value, nil
}

func DecodeTypedJSON[T any](reader io.Reader, maxBytes int64) (T, error) {
	var out T
	value, err := DecodeJSON(reader, maxBytes)
	if err != nil {
		return out, err
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return out, fmt.Errorf("normalize admitted JSON: %w", err)
	}
	if err := json.Unmarshal(normalized, &out); err != nil {
		return out, fmt.Errorf("decode admitted JSON: %w", err)
	}
	return out, nil
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("maxBytes must be positive")
	}
	limited := io.LimitReader(reader, maxBytes+1)
	source, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(source)) > maxBytes {
		return nil, errors.New("invalid JSON input: exceeds resource limit")
	}
	return source, nil
}

type jsonKeyScanner struct {
	source []byte
	index  int
}

func assertUniqueObjectKeys(source []byte) error {
	scanner := jsonKeyScanner{source: source}
	if err := scanner.parseValue(); err != nil {
		return err
	}
	scanner.skipWhitespace()
	if scanner.index != len(scanner.source) {
		return errors.New("invalid JSON input: multiple JSON values")
	}
	return nil
}

func (scanner *jsonKeyScanner) skipWhitespace() {
	for scanner.index < len(scanner.source) && unicode.IsSpace(rune(scanner.source[scanner.index])) {
		scanner.index++
	}
}

func (scanner *jsonKeyScanner) parseValue() error {
	scanner.skipWhitespace()
	if scanner.index >= len(scanner.source) {
		return errors.New("invalid JSON input: unexpected end")
	}
	switch scanner.source[scanner.index] {
	case '{':
		return scanner.parseObject()
	case '[':
		return scanner.parseArray()
	case '"':
		_, err := scanner.parseString()
		return err
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		scanner.parseNumberLike()
		return nil
	case 't':
		return scanner.consumeLiteral("true")
	case 'f':
		return scanner.consumeLiteral("false")
	case 'n':
		return scanner.consumeLiteral("null")
	default:
		return errors.New("invalid JSON input: unexpected token")
	}
}

func (scanner *jsonKeyScanner) parseObject() error {
	scanner.index++
	seen := map[string]struct{}{}
	scanner.skipWhitespace()
	if scanner.index < len(scanner.source) && scanner.source[scanner.index] == '}' {
		scanner.index++
		return nil
	}
	for scanner.index < len(scanner.source) {
		scanner.skipWhitespace()
		if scanner.index >= len(scanner.source) || scanner.source[scanner.index] != '"' {
			return errors.New("invalid JSON input: object key must be a string")
		}
		key, err := scanner.parseString()
		if err != nil {
			return err
		}
		if _, ok := seen[key]; ok {
			return errors.New("invalid JSON input: duplicate object key")
		}
		seen[key] = struct{}{}
		scanner.skipWhitespace()
		if scanner.index >= len(scanner.source) || scanner.source[scanner.index] != ':' {
			return errors.New("invalid JSON input: object key must be followed by colon")
		}
		scanner.index++
		if err := scanner.parseValue(); err != nil {
			return err
		}
		scanner.skipWhitespace()
		if scanner.index < len(scanner.source) && scanner.source[scanner.index] == '}' {
			scanner.index++
			return nil
		}
		if scanner.index >= len(scanner.source) || scanner.source[scanner.index] != ',' {
			return errors.New("invalid JSON input: object entries must be separated by comma")
		}
		scanner.index++
	}
	return errors.New("invalid JSON input: unterminated object")
}

func (scanner *jsonKeyScanner) parseArray() error {
	scanner.index++
	scanner.skipWhitespace()
	if scanner.index < len(scanner.source) && scanner.source[scanner.index] == ']' {
		scanner.index++
		return nil
	}
	for scanner.index < len(scanner.source) {
		if err := scanner.parseValue(); err != nil {
			return err
		}
		scanner.skipWhitespace()
		if scanner.index < len(scanner.source) && scanner.source[scanner.index] == ']' {
			scanner.index++
			return nil
		}
		if scanner.index >= len(scanner.source) || scanner.source[scanner.index] != ',' {
			return errors.New("invalid JSON input: array values must be separated by comma")
		}
		scanner.index++
	}
	return errors.New("invalid JSON input: unterminated array")
}

func (scanner *jsonKeyScanner) parseString() (string, error) {
	start := scanner.index
	scanner.index++
	for scanner.index < len(scanner.source) {
		switch scanner.source[scanner.index] {
		case '\\':
			scanner.index += 2
		case '"':
			scanner.index++
			var value string
			if err := json.Unmarshal(scanner.source[start:scanner.index], &value); err != nil {
				return "", fmt.Errorf("invalid JSON input: %w", err)
			}
			return value, nil
		default:
			scanner.index++
		}
	}
	return "", errors.New("invalid JSON input: unterminated string")
}

func (scanner *jsonKeyScanner) parseNumberLike() {
	for scanner.index < len(scanner.source) {
		switch scanner.source[scanner.index] {
		case ' ', '\n', '\r', '\t', ',', ']', '}':
			return
		default:
			scanner.index++
		}
	}
}

func (scanner *jsonKeyScanner) consumeLiteral(literal string) error {
	if !bytes.HasPrefix(scanner.source[scanner.index:], []byte(literal)) {
		return errors.New("invalid JSON input: unexpected token")
	}
	scanner.index += len(literal)
	return nil
}
