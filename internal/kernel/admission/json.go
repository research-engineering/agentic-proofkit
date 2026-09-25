package admission

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxJSONNestingDepth = 512

func DecodeJSON(reader io.Reader, maxBytes int64) (any, error) {
	source, err := readBounded(reader, maxBytes)
	if err != nil {
		return nil, err
	}
	return decodeJSONSource(source)
}

func decodeJSONSource(source []byte) (any, error) {
	if !utf8.Valid(source) {
		return nil, errors.New("invalid JSON input: source must be valid UTF-8")
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

// DecodeTypedJSON validates JSON syntax and exact spelling of known struct keys.
// Unknown keys remain permitted; callers own closed-object admission. Target
// fields are inspected only for present ordinary struct-object values. Reserved
// quote/backslash names and options other than omitempty, omitzero and string
// are unsupported there. Custom JSON unmarshalers own their representations;
// text-only unmarshalers do not bypass object-key checking.
func DecodeTypedJSON[T any](reader io.Reader, maxBytes int64) (T, error) {
	var out T
	source, err := readBounded(reader, maxBytes)
	if err != nil {
		return out, err
	}
	value, err := decodeJSONSource(source)
	if err != nil {
		return out, err
	}
	if err := rejectCaseFoldedTypedKeys(value, reflect.TypeOf((*T)(nil)).Elem()); err != nil {
		return out, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return out, fmt.Errorf("decode admitted JSON: %w", err)
	}
	return out, nil
}

func rejectCaseFoldedTypedKeys(value any, target reflect.Type) error {
	return rejectCaseFoldedKeys(value, target, map[reflect.Type]map[string]reflect.Type{})
}

func rejectCaseFoldedKeys(value any, target reflect.Type, targetFields map[reflect.Type]map[string]reflect.Type) error {
	if value == nil {
		return nil
	}
	target, err := indirectJSONType(target)
	if err != nil {
		return err
	}
	if target == nil || target.Kind() == reflect.Interface || isOpaqueJSONType(target) {
		return nil
	}
	switch target.Kind() {
	case reflect.Struct:
		record, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields, found := targetFields[target]
		if !found {
			fields, err = jsonStructFields(target)
			if err != nil {
				return err
			}
			targetFields[target] = fields
		}
		for key, child := range record {
			fieldType, exact := fields[key]
			if !exact {
				canonicalName := ""
				for canonical := range fields {
					if strings.EqualFold(key, canonical) && (canonicalName == "" || canonical < canonicalName) {
						canonicalName = canonical
					}
				}
				// Pick a stable spelling without sorting fields for each child.
				if canonicalName != "" {
					return fmt.Errorf("invalid JSON input: object key must use exact declared field %q", canonicalName)
				}
				continue
			}
			if err := rejectCaseFoldedKeys(child, fieldType, targetFields); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, child := range values {
			if err := rejectCaseFoldedKeys(child, target.Elem(), targetFields); err != nil {
				return err
			}
		}
	case reflect.Map:
		record, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, child := range record {
			if err := rejectCaseFoldedKeys(child, target.Elem(), targetFields); err != nil {
				return err
			}
		}
	}
	return nil
}

func indirectJSONType(target reflect.Type) (reflect.Type, error) {
	seen := map[reflect.Type]bool{}
	for target != nil && target.Kind() == reflect.Pointer {
		if seen[target] {
			return nil, errors.New("invalid JSON target schema: unsupported pointer cycle")
		}
		seen[target] = true
		target = target.Elem()
	}
	return target, nil
}

func isOpaqueJSONType(target reflect.Type) bool {
	return hasJSONMethod(target, reflect.TypeFor[json.Unmarshaler](), reflect.TypeFor[jsonv2.UnmarshalerFrom]())
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
	depth  int
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
	scanner.depth++
	defer func() { scanner.depth-- }()
	if scanner.depth > maxJSONNestingDepth {
		return errors.New("invalid JSON input: exceeds nesting depth limit")
	}
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
		_, err := scanner.parseStringToken()
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
	token, err := scanner.parseStringToken()
	if err != nil {
		return "", err
	}
	var value string
	if err := json.Unmarshal(token, &value); err != nil {
		return "", fmt.Errorf("invalid JSON input: %w", err)
	}
	return value, nil
}

func (scanner *jsonKeyScanner) parseStringToken() ([]byte, error) {
	start := scanner.index
	scanner.index++
	for scanner.index < len(scanner.source) {
		switch scanner.source[scanner.index] {
		case '\\':
			scanner.index += 2
		case '"':
			scanner.index++
			token := scanner.source[start:scanner.index]
			if err := validateJSONStringUnicodeEscapes(token); err != nil {
				return nil, err
			}
			if !json.Valid(token) {
				return nil, errors.New("invalid JSON input: invalid string token")
			}
			return token, nil
		default:
			scanner.index++
		}
	}
	return nil, errors.New("invalid JSON input: unterminated string")
}

func validateJSONStringUnicodeEscapes(token []byte) error {
	for index := 1; index < len(token)-1; index++ {
		if token[index] != '\\' {
			continue
		}
		index++
		if index >= len(token)-1 || token[index] != 'u' {
			continue
		}
		codePoint, ok := decodeHexQuad(token, index+1)
		if !ok {
			continue
		}
		index += 4
		switch {
		case codePoint >= 0xd800 && codePoint <= 0xdbff:
			if index+6 >= len(token) || token[index+1] != '\\' || token[index+2] != 'u' {
				return errors.New("invalid JSON input: unpaired Unicode surrogate")
			}
			low, ok := decodeHexQuad(token, index+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return errors.New("invalid JSON input: unpaired Unicode surrogate")
			}
			index += 6
		case codePoint >= 0xdc00 && codePoint <= 0xdfff:
			return errors.New("invalid JSON input: unpaired Unicode surrogate")
		}
	}
	return nil
}

func decodeHexQuad(source []byte, start int) (uint16, bool) {
	if start+4 > len(source) {
		return 0, false
	}
	var value uint16
	for _, character := range source[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
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
