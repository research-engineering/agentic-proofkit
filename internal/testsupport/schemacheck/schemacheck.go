// Package schemacheck evaluates the draft 2020-12 keyword subset used by
// native structural owners so Go tests can compare published schemas with
// native admission. It fails closed on any keyword it does not implement and
// is test support only: it is not a schema authority or an admission path.
package schemacheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

var annotations = map[string]bool{"$schema": true, "$defs": true, "description": true, "default": true, "x-proofkit-number-encoding": true}

// Normalize serializes a Go value and decodes it with json.Number, matching
// the public wire form of native outputs before validation.
func Normalize(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// Validate returns nil when value is accepted by schema. Unsupported keywords
// or references return an error rather than being ignored.
func Validate(schema map[string]any, value any) error {
	normalized, err := Normalize(value)
	if err != nil {
		return err
	}
	return (evaluator{root: schema}).check(schema, normalized, "$")
}

type evaluator struct{ root map[string]any }

// unsupportedSchemaError marks a schema outside the implemented subset. It is
// never a mismatch: not, oneOf, anyOf, allOf and contains return it at once
// instead of counting it, so an unsupported subschema cannot turn into
// acceptance.
type unsupportedSchemaError struct{ message string }

func (e unsupportedSchemaError) Error() string { return e.message }

func unsupported(format string, arguments ...any) error {
	return unsupportedSchemaError{message: fmt.Sprintf(format, arguments...)}
}

// matches reports whether value is accepted by schema; an unsupported schema
// is returned as an error rather than as a mismatch.
func (e evaluator) matches(schema any, value any, path string) (bool, error) {
	err := e.check(schema, value, path)
	var unsupportedSchema unsupportedSchemaError
	if errors.As(err, &unsupportedSchema) {
		return false, err
	}
	return err == nil, nil
}

func (e evaluator) check(raw any, value any, path string) error {
	if raw == true {
		return nil
	}
	if raw == false {
		return fmt.Errorf("%s: false schema", path)
	}
	schema, ok := raw.(map[string]any)
	if !ok {
		return unsupported("%s: unsupported schema node %T", path, raw)
	}
	for _, key := range sortedKeys(schema) {
		if err := e.keyword(schema, key, value, path); err != nil {
			return err
		}
	}
	return nil
}

func (e evaluator) keyword(schema map[string]any, key string, value any, path string) error {
	argument := schema[key]
	switch key {
	case "$ref":
		reference, _ := argument.(string)
		name, ok := strings.CutPrefix(reference, "#/$defs/")
		definitions, _ := e.root["$defs"].(map[string]any)
		target, found := definitions[name]
		if !ok || !found || strings.Contains(name, "/") {
			return unsupported("%s: unsupported reference %q", path, reference)
		}
		return e.check(target, value, path)
	case "type":
		return checkType(argument, value, path)
	case "const":
		if !equal(argument, value) {
			return fmt.Errorf("%s: const mismatch", path)
		}
	case "enum":
		values, _ := argument.([]any)
		if !slices.ContainsFunc(values, func(item any) bool { return equal(item, value) }) {
			return fmt.Errorf("%s: enum mismatch", path)
		}
	case "pattern":
		if text, ok := value.(string); ok {
			pattern, err := goPattern(argument.(string))
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			if !pattern.MatchString(text) {
				return fmt.Errorf("%s: pattern mismatch", path)
			}
		}
	case "minLength", "maxLength":
		if text, ok := value.(string); ok {
			length, bound := big.NewRat(int64(utf8.RuneCountInString(text)), 1), number(argument)
			if (key == "minLength" && length.Cmp(bound) < 0) || (key == "maxLength" && length.Cmp(bound) > 0) {
				return fmt.Errorf("%s: %s violation", path, key)
			}
		}
	case "minimum", "maximum":
		if actual, ok := value.(json.Number); ok {
			comparison := number(actual).Cmp(number(argument))
			if (key == "minimum" && comparison < 0) || (key == "maximum" && comparison > 0) {
				return fmt.Errorf("%s: %s violation", path, key)
			}
		}
	case "properties", "required", "additionalProperties", "maxProperties", "minProperties":
		if record, ok := value.(map[string]any); ok {
			return e.object(schema, key, record, path)
		}
	case "items", "prefixItems", "minItems", "maxItems", "uniqueItems", "contains":
		if items, ok := value.([]any); ok {
			return e.array(schema, key, items, path)
		}
	case "oneOf", "anyOf", "allOf":
		alternatives, _ := argument.([]any)
		matches := 0
		for _, alternative := range alternatives {
			matched, err := e.matches(alternative, value, path)
			if err != nil {
				return err
			}
			if matched {
				matches++
			}
		}
		if (key == "oneOf" && matches != 1) || (key == "anyOf" && matches == 0) || (key == "allOf" && matches != len(alternatives)) {
			return fmt.Errorf("%s: %s matched %d of %d", path, key, matches, len(alternatives))
		}
	case "not":
		matched, err := e.matches(argument, value, path)
		if err != nil {
			return err
		}
		if matched {
			return fmt.Errorf("%s: not matched", path)
		}
	default:
		if !annotations[key] {
			return unsupported("%s: unsupported keyword %s", path, key)
		}
	}
	return nil
}

func (e evaluator) object(schema map[string]any, key string, record map[string]any, path string) error {
	properties, _ := schema["properties"].(map[string]any)
	switch key {
	case "properties":
		for _, name := range sortedKeys(record) {
			if child, declared := properties[name]; declared {
				if err := e.check(child, record[name], path+"."+name); err != nil {
					return err
				}
			}
		}
	case "required":
		for _, raw := range schema["required"].([]any) {
			if _, present := record[raw.(string)]; !present {
				return fmt.Errorf("%s: missing required %s", path, raw)
			}
		}
	case "additionalProperties":
		for _, name := range sortedKeys(record) {
			if _, declared := properties[name]; !declared {
				if err := e.check(schema["additionalProperties"], record[name], path+"."+name); err != nil {
					return err
				}
			}
		}
	case "maxProperties", "minProperties":
		count, bound := big.NewRat(int64(len(record)), 1), number(schema[key])
		if (key == "minProperties" && count.Cmp(bound) < 0) || (key == "maxProperties" && count.Cmp(bound) > 0) {
			return fmt.Errorf("%s: %s violation", path, key)
		}
	}
	return nil
}

func (e evaluator) array(schema map[string]any, key string, items []any, path string) error {
	prefix, _ := schema["prefixItems"].([]any)
	switch key {
	case "prefixItems":
		for index := 0; index < len(prefix) && index < len(items); index++ {
			if err := e.check(prefix[index], items[index], fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case "items":
		for index := len(prefix); index < len(items); index++ {
			if err := e.check(schema["items"], items[index], fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case "minItems", "maxItems":
		count, bound := big.NewRat(int64(len(items)), 1), number(schema[key])
		if (key == "minItems" && count.Cmp(bound) < 0) || (key == "maxItems" && count.Cmp(bound) > 0) {
			return fmt.Errorf("%s: %s violation", path, key)
		}
	case "uniqueItems":
		if schema["uniqueItems"] == true {
			for left := range items {
				for right := left + 1; right < len(items); right++ {
					if equal(items[left], items[right]) {
						return fmt.Errorf("%s: duplicate items", path)
					}
				}
			}
		}
	case "contains":
		for _, item := range items {
			matched, err := e.matches(schema["contains"], item, path)
			if err != nil || matched {
				return err
			}
		}
		return fmt.Errorf("%s: contains mismatch", path)
	}
	return nil
}

func checkType(argument any, value any, path string) error {
	name, _ := argument.(string)
	ok := false
	switch name {
	case "object":
		_, ok = value.(map[string]any)
	case "array":
		_, ok = value.([]any)
	case "string":
		_, ok = value.(string)
	case "boolean":
		_, ok = value.(bool)
	case "null":
		ok = value == nil
	case "number":
		_, ok = value.(json.Number)
	case "integer":
		actual, isNumber := value.(json.Number)
		ok = isNumber && number(actual).IsInt()
	default:
		return unsupported("%s: unsupported type %v", path, argument)
	}
	if !ok {
		return fmt.Errorf("%s: expected %s", path, name)
	}
	return nil
}

// JSON Schema compares numbers mathematically, not by token spelling.
func number(raw any) *big.Rat {
	var text string
	switch typed := raw.(type) {
	case json.Number:
		text = typed.String()
	case int:
		text = fmt.Sprint(typed)
	case int64:
		text = fmt.Sprint(typed)
	case float64:
		text = fmt.Sprint(typed)
	default:
		panic(fmt.Sprintf("schemacheck: non-numeric bound %T", raw))
	}
	value, ok := new(big.Rat).SetString(text)
	if !ok {
		panic("schemacheck: invalid number " + text)
	}
	return value
}

func equal(left, right any) bool {
	switch typed := left.(type) {
	case json.Number, int, int64, float64:
		switch right.(type) {
		case json.Number, int, int64, float64:
			return number(typed).Cmp(number(right)) == 0
		}
		return false
	case map[string]any:
		other, ok := right.(map[string]any)
		if !ok || len(other) != len(typed) {
			return false
		}
		for key, value := range typed {
			if candidate, present := other[key]; !present || !equal(value, candidate) {
				return false
			}
		}
		return true
	case []any:
		other, ok := right.([]any)
		if !ok || len(other) != len(typed) {
			return false
		}
		for index := range typed {
			if !equal(typed[index], other[index]) {
				return false
			}
		}
		return true
	default:
		return left == right
	}
}

var (
	unicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	patternMutex  sync.Mutex
	patternCache  = map[string]*regexp.Regexp{}
)

// The published patterns use ECMAScript escapes and an end-of-input
// lookahead; only those two forms are translated to RE2.
func goPattern(source string) (*regexp.Regexp, error) {
	patternMutex.Lock()
	defer patternMutex.Unlock()
	if compiled, ok := patternCache[source]; ok {
		return compiled, nil
	}
	translated := strings.ReplaceAll(source, `(?![\s\S])`, `\z`)
	translated = unicodeEscape.ReplaceAllString(translated, `\x{$1}`)
	if strings.Contains(translated, "(?=") || strings.Contains(translated, "(?!") || strings.Contains(translated, "(?<") {
		return nil, unsupported("unsupported pattern lookaround %q", source)
	}
	compiled, err := regexp.Compile(translated)
	if err != nil {
		return nil, unsupported("unsupported pattern %q: %v", source, err)
	}
	patternCache[source] = compiled
	return compiled, nil
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
