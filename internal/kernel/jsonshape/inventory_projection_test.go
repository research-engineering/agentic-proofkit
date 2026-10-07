package jsonshape

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func TestRequiredObjectPreservesItsExactInventory(t *testing.T) {
	names := []string{"second", "first"}
	fields := map[string]Shape{"first": String(), "second": Boolean()}
	shape := RequiredObject(names, fields)
	names[0], fields["first"] = "changed", Boolean()
	if _, err := shape.Admit(map[string]any{"first": "value", "second": true}, "object"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(shape.JSONSchema()["required"], []any{"first", "second"}) {
		t.Fatal("required inventory changed")
	}
	for _, value := range []map[string]any{
		{"first": "value"}, {"first": false, "second": true},
		{"first": "value", "second": true, "extra": nil},
	} {
		if _, err := shape.Admit(value, "object"); err == nil {
			t.Fatalf("invalid inventory value admitted: %#v", value)
		}
	}
	for _, test := range []struct {
		name   string
		names  []string
		fields map[string]Shape
	}{
		{"missing", []string{"a"}, map[string]Shape{}},
		{"extra", []string{"a"}, map[string]Shape{"a": String(), "b": String()}},
		{"different", []string{"a"}, map[string]Shape{"b": String()}},
		{"duplicate", []string{"a", "a"}, map[string]Shape{"a": String(), "b": String()}},
		{"invalid", []string{"a"}, map[string]Shape{"a": {}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid declaration did not fail closed")
				}
			}()
			RequiredObject(test.names, test.fields)
		})
	}
}

func TestTrimSpacePatternClassMatchesNativeWhitespace(t *testing.T) {
	decoded, err := strconv.Unquote(`"` + TrimSpacePatternClass() + `"`)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[rune]bool{}
	for _, r := range decoded {
		if declared[r] {
			t.Fatal("whitespace class repeats a rune")
		}
		declared[r] = true
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if declared[r] != (strings.TrimSpace(string(r)) == "") {
			t.Fatalf("whitespace projection differs at U+%04X", r)
		}
	}
}

func TestObjectFromKeysPreservesOptionalInventory(t *testing.T) {
	names := []string{"value", "id", "nullable"}
	fields := map[string]Shape{"id": String(), "value": String(), "nullable": Nullable(String())}
	optional := []string{"value", "nullable"}
	shape := ObjectFromKeys(names, fields, optional...)
	names[0], fields["id"], optional[0] = "changed", Boolean(), "id"
	if !reflect.DeepEqual(shape.JSONSchema()["required"], []any{"id"}) {
		t.Fatal("optional subset changed the required inventory")
	}
	for _, value := range []map[string]any{
		{"id": "record"},
		{"id": "record", "value": "", "nullable": nil},
		{"id": "record", "value": "text", "nullable": "text"},
	} {
		admitted, err := shape.Admit(value, "object")
		if err != nil || !reflect.DeepEqual(admitted, value) {
			t.Fatalf("valid optional object changed: %v", err)
		}
	}
	for _, value := range []map[string]any{
		{}, {"value": "text"}, {"id": nil}, {"id": false},
		{"id": "record", "value": nil}, {"id": "record", "nullable": false},
		{"id": "record", "extra": nil},
	} {
		if _, err := shape.Admit(value, "object"); err == nil {
			t.Fatal("invalid optional object admitted")
		}
	}
	for _, optional := range [][]string{{"unknown"}, {"value", "value"}, {""}} {
		t.Run(strings.Join(optional, "/"), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid optional declaration did not fail closed")
				}
			}()
			ObjectFromKeys([]string{"value"}, map[string]Shape{"value": String()}, optional...)
		})
	}
}

func TestBoundedStringGrammarPreservesCodePointLimits(t *testing.T) {
	shape := BoundedStringGrammar(`[\s\S]+`, 2)
	for _, value := range []string{"a", "ab", "\u00e9\U0001f600"} {
		if admitted, err := shape.Admit(value, "text"); err != nil || admitted != value {
			t.Fatalf("bounded grammar changed a valid value: %v", err)
		}
	}
	for _, value := range []any{"", "abc", "\u00e9\U0001f600x", true} {
		if _, err := shape.Admit(value, "text"); err == nil {
			t.Fatal("bounded grammar admitted an invalid value")
		}
	}
	if shape.JSONSchema()["maxLength"] != json.Number("2") {
		t.Fatal("JSON Schema bound differs from the native bound")
	}
	if _, err := BoundedStringGrammar(`[a-z]+`, 2).Admit("A", "identifier"); err == nil {
		t.Fatal("length bound replaced the grammar check")
	}
	unbounded := StringGrammar(`[\s\S]+`)
	if _, err := unbounded.Admit("abc", "text"); err != nil {
		t.Fatal(err)
	}
	if _, present := unbounded.JSONSchema()["maxLength"]; present {
		t.Fatal("unbounded grammar acquired a bound")
	}
	for _, maximum := range []int{0, -1} {
		t.Run(strconv.Itoa(maximum), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid bound accepted")
				}
			}()
			BoundedStringGrammar(`[a-z]+`, maximum)
		})
	}
}
