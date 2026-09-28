package jsonshape

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestIntegerRangePreservesTokenDomainAndBoundaries(t *testing.T) {
	shape := IntegerRange(-2, 3)
	for _, test := range []struct {
		raw   any
		valid bool
	}{
		{json.Number("-2"), true}, {json.Number("-1"), true}, {json.Number("-0"), true},
		{json.Number("0"), true}, {json.Number("3"), true},
		{json.Number("-3"), false}, {json.Number("4"), false},
		{json.Number("3.0"), false}, {json.Number("1e0"), false},
		{json.Number("01"), false}, {json.Number("+1"), false}, {json.Number("-00"), false},
		{json.Number(" 1"), false}, {json.Number("9223372036854775808"), false},
		{json.Number("-9223372036854775809"), false}, {json.Number(strings.Repeat("1", 1024)), false},
		{nil, false}, {"1", false}, {true, false}, {1, false}, {int64(1), false}, {1.0, false},
	} {
		got, err := shape.Admit(test.raw, "limit")
		if (err == nil) != test.valid || (test.valid && got != test.raw) {
			t.Fatalf("integer domain or token drift for %T: %v", test.raw, err)
		}
		if err := shape.CheckGenerated(test.raw, "limit"); (err == nil) != (test.valid || test.raw == 1) {
			t.Fatalf("generated carrier domain drift for %T: %v", test.raw, err)
		}
	}
	for _, token := range []json.Number{"-9223372036854775808", "9223372036854775807"} {
		got, err := IntegerRange(math.MinInt64, math.MaxInt64).Admit(token, "limit")
		if err != nil || got != token {
			t.Fatalf("int64 endpoint lost: %v", err)
		}
	}
	if _, err := IntegerRange(1, 3).Admit(json.Number("-0"), "limit"); err == nil {
		t.Fatal("negative zero bypassed the lower bound")
	}
	if _, err := IntegerMinimum(0).Admit(json.Number("-0"), "limit"); err == nil {
		t.Fatal("existing canonical integer domain widened")
	}
	if _, err := shape.Admit(json.Number("untrusted-integer-token"), "limit"); err == nil || strings.Contains(err.Error(), "untrusted-integer-token") {
		t.Fatal("numeric diagnostic echoed caller text")
	}
}

func TestIntegerRangeDefaultsAreDetachedAnnotations(t *testing.T) {
	original := Nullable(IntegerRange(0, 3))
	annotated := WithIntegerDefault(original, 2)
	want := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "default": json.Number("2"),
		"anyOf": []any{map[string]any{"type": "null"}, map[string]any{
			"type": "integer", "minimum": json.Number("0"), "maximum": json.Number("3"),
			"x-proofkit-number-encoding": "decimal-integer-token-int64",
		}},
	}
	schema := annotated.JSONSchema()
	if !reflect.DeepEqual(schema, want) {
		t.Fatal("integer range/default schema drift")
	}
	schema["default"] = json.Number("3")
	schema["anyOf"].([]any)[1].(map[string]any)["maximum"] = json.Number("4")
	if !reflect.DeepEqual(annotated.JSONSchema(), want) {
		t.Fatal("schema projection aliases its declaration")
	}
	if _, exists := original.JSONSchema()["default"]; exists {
		t.Fatal("annotation changed the original shape")
	}
	for _, raw := range []any{nil, json.Number("-0"), json.Number("3")} {
		got, err := annotated.Admit(raw, "limit")
		if err != nil || got != raw {
			t.Fatalf("default inserted or changed an admitted value: %v", err)
		}
	}
	for _, invalid := range []func(){
		func() { IntegerRange(3, 2) },
		func() { WithIntegerDefault(Shape{}, 1) },
		func() { WithIntegerDefault(String(), 1) },
		func() { WithIntegerDefault(IntegerRange(1, 3), 0) },
		func() { WithIntegerDefault(IntegerRange(1, 3), 4) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid integer declaration admitted")
				}
			}()
			invalid()
		}()
	}
}
