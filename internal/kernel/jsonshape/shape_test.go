package jsonshape

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNullOnlyFieldsPreservePresenceAndRejectOtherValues(t *testing.T) {
	shape := Object(Required("required", Null()), Optional("optional", Null()))
	for _, raw := range []any{map[string]any{"required": nil}, map[string]any{"required": nil, "optional": nil}} {
		if _, err := shape.Admit(raw, "record"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := shape.Admit(map[string]any{}, "record"); err == nil {
		t.Fatal("missing is not null")
	}
	for _, raw := range []any{"", false, json.Number("0"), []any{}, map[string]any{}} {
		if _, err := Null().Admit(raw, "null"); err == nil {
			t.Fatalf("null admitted non-null %T", raw)
		}
		if err := Nullable(Null()).CheckGenerated(raw, "null"); err == nil {
			t.Fatal("nullable null widened to a non-null value")
		}
	}
	if got := Null().JSONSchema(); got["type"] != "null" || len(got) != 2 {
		t.Fatalf("null schema drift: %#v", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("non-null null-only declaration must fail closed")
		}
	}()
	NonNullable(Null())
}

func TestDiscriminatedUnionMatchesItsExclusiveSum(t *testing.T) {
	left := Object(Required("kind", StringLiteral("left")), Required("text", String()))
	right := Object(Required("kind", StringLiteral("right")), Required("items", Array(String(), 0)))
	alternatives := []Shape{left, right}
	tagged := DiscriminatedUnion("kind", alternatives...)
	plain := OneOf(alternatives...)
	alternatives[0] = String()
	if !reflect.DeepEqual(tagged.JSONSchema(), plain.JSONSchema()) {
		t.Fatal("tag selection changed the exclusive sum schema")
	}
	for _, tc := range []struct {
		raw   any
		valid bool
	}{
		{map[string]any{"kind": "left", "text": "value"}, true},
		{map[string]any{"kind": "right", "items": []any{"value"}}, true},
		{map[string]any{"kind": "left", "text": "value", "items": []any{}}, false},
		{map[string]any{"kind": "left"}, false},
		{map[string]any{"kind": "other"}, false}, {map[string]any{"kind": nil}, false},
		{map[string]any{}, false}, {nil, false}, {"left", false},
	} {
		_, err := tagged.Admit(tc.raw, "record")
		_, plainErr := plain.Admit(tc.raw, "record")
		if (err == nil) != tc.valid || (plainErr == nil) != tc.valid {
			t.Fatalf("union domain drift: %v / %v", err, plainErr)
		}
		if err := tagged.CheckGenerated(tc.raw, "record"); (err == nil) != tc.valid {
			t.Fatalf("generated domain drift: %v", err)
		}
	}
	if _, err := tagged.Admit(map[string]any{"kind": "left"}, "record"); err == nil || !strings.Contains(err.Error(), ".text") {
		t.Fatalf("selected branch lost useful diagnostic: %v", err)
	}
	for _, bad := range []Shape{
		String(), Nullable(left), Object(Required("text", String())),
		Object(Optional("kind", StringLiteral("tag"))), Object(Required("kind", Nullable(StringLiteral("tag")))),
		Object(Required("kind", String())), left,
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid discriminator declaration admitted")
				}
			}()
			DiscriminatedUnion("kind", left, bad)
		}()
	}
}

func TestGeneratedCheckingDoesNotWidenCallerNumericAdmission(t *testing.T) {
	shape := Object(Required("version", IntegerLiteral(2)), Required("counts", Tuple(IntegerMinimum(0), IntegerMinimum(4))))
	for _, tc := range []struct {
		name              string
		counts            []any
		version           any
		caller, generated bool
	}{
		{"wire", []any{json.Number("0"), json.Number("4")}, json.Number("2"), true, true},
		{"native", []any{0, 4}, 2, false, true},
		{"lower bound", []any{0, 3}, 2, false, false},
		{"negative", []any{-1, 4}, 2, false, false},
		{"float", []any{0.0, 4}, 2, false, false},
		{"int64 carrier", []any{int64(0), 4}, 2, false, false},
		{"short tuple", []any{0}, 2, false, false},
		{"long tuple", []any{0, 4, 5}, 2, false, false},
		{"wrong version", []any{0, 4}, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]any{"version": tc.version, "counts": tc.counts}
			before := fmt.Sprintf("%#v", raw)
			_, err := shape.Admit(raw, "caller")
			if (err == nil) != tc.caller {
				t.Fatalf("caller admission: %v", err)
			}
			err = shape.CheckGenerated(raw, "generated")
			if (err == nil) != tc.generated {
				t.Fatalf("generated check: %v", err)
			}
			if before != fmt.Sprintf("%#v", raw) {
				t.Fatal("generated check mutated its input")
			}
		})
	}
	for _, token := range []string{"-0", "01", "+1", "1e1", "4.0", "9223372036854775808", "false"} {
		for _, check := range []func(any) error{
			func(raw any) error { _, err := IntegerMinimum(0).Admit(raw, "count"); return err },
			func(raw any) error { return IntegerMinimum(0).CheckGenerated(raw, "count") },
		} {
			if err := check(json.Number(token)); err == nil {
				t.Fatalf("accepted noncanonical count %q", token)
			}
		}
	}
	if _, err := IntegerMinimum(0).Admit(json.Number("9223372036854775807"), "count"); err != nil {
		t.Fatal(err)
	}
}

func TestTupleStructureAndGeneratedCheckHaveNoProjectionCopies(t *testing.T) {
	items := []Shape{String(), IntegerMinimum(0)}
	shape := Tuple(items...)
	items[0] = IntegerLiteral(9)
	if _, err := shape.Admit([]any{"x", json.Number("1")}, "tuple"); err != nil {
		t.Fatal("tuple constructor retained the caller slice", err)
	}
	want := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "array", "items": false,
		"minItems": 2, "maxItems": 2, "prefixItems": []any{map[string]any{"type": "string"}, map[string]any{"type": "integer", "minimum": json.Number("0"), "maximum": json.Number("9223372036854775807"), "x-proofkit-number-encoding": "canonical-int64"}},
	}
	if !reflect.DeepEqual(shape.JSONSchema(), want) {
		t.Fatal("tuple schema changed its independent structural predicate")
	}
	if !reflect.DeepEqual(Tuple().JSONSchema(), map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "array", "items": false, "minItems": 0, "maxItems": 0}) {
		t.Fatal("empty tuple emitted invalid or unbounded schema")
	}
	for _, raw := range []any{nil, []any{"extra"}, ""} {
		if err := Tuple().CheckGenerated(raw, "empty"); err == nil {
			t.Fatal("nonempty/nonarray empty tuple accepted")
		}
	}
	rows := make([]any, 1000)
	for i := range rows {
		rows[i] = map[string]any{"id": "stable"}
	}
	collection := Array(Object(Required("id", String())), 0)
	if err := collection.CheckGenerated(rows, "rows"); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(10, func() {
		if err := collection.CheckGenerated(rows, "rows"); err != nil {
			panic(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("generated checking copied the record tree: %g allocations", allocs)
	}
}

func TestSourceOperatorsRetainTypesBoundsAndCanonicalCoordinates(t *testing.T) {
	for _, tc := range []struct {
		shape    Shape
		accepted []any
		rejected []any
	}{
		{Boolean(), []any{true, false}, []any{nil, "true", 0, json.Number("1")}},
		{StringLiteral("source"), []any{"source"}, []any{nil, " source", "other", true}},
		{StringLiteral(""), []any{""}, []any{nil, "source"}},
		{DecimalIntegerString(), []any{"0", "-1", "9223372036854775807", "-9223372036854775808"}, []any{"-0", "01", "+1", "1.0", "1e0", "9223372036854775808", nil, json.Number("1"), 1}},
		{BoundedArray(String(), 1, 2), []any{[]any{"a"}, []any{"a", "b"}}, []any{nil, []any{}, []any{"a", "b", "c"}, []any{true}}},
		{StringMap(1), []any{map[string]any{}, map[string]any{"caller.name": "value"}}, []any{nil, []any{}, map[string]any{"a": "x", "b": "y"}, map[string]any{"a": true}}},
	} {
		for _, raw := range tc.accepted {
			admitted, err := tc.shape.Admit(raw, "source")
			if err != nil || !reflect.DeepEqual(admitted, raw) {
				t.Fatalf("accepted domain changed for %T: %v", raw, err)
			}
			if err := tc.shape.CheckGenerated(raw, "source"); err != nil {
				t.Fatal(err)
			}
		}
		for _, raw := range tc.rejected {
			if _, err := tc.shape.Admit(raw, "source"); err == nil {
				t.Fatalf("wrong source operand accepted: %#v", raw)
			}
			if err := tc.shape.CheckGenerated(raw, "source"); err == nil {
				t.Fatalf("wrong generated source operand accepted: %#v", raw)
			}
		}
	}
	for _, shape := range []Shape{BoundedArray(String(), 0, 0), StringMap(0)} {
		var raw any = []any{true}
		if shape.node.kind == stringMapKind {
			raw = map[string]any{"private-key": true}
		}
		if _, err := shape.Admit(raw, "source"); err == nil || !strings.Contains(err.Error(), "at most 0") || strings.Contains(err.Error(), "private-key") {
			t.Fatalf("bound did not dominate item inspection: %v", err)
		}
	}
	shape := Object(Required("items", BoundedArray(StringMap(2), 0, 3)))
	array, ok := shape.Property("items")
	if !ok {
		t.Fatal("missing owned property")
	}
	element, ok := array.Element()
	if !ok {
		t.Fatal("missing owned element")
	}
	first := element.JSONSchema()
	first["additionalProperties"].(map[string]any)["type"] = "boolean"
	if element.JSONSchema()["additionalProperties"].(map[string]any)["type"] != "string" {
		t.Fatal("child projection aliases its owner")
	}
	if _, ok := shape.Property("unknown"); ok {
		t.Fatal("unknown child invented")
	}
	if _, ok := shape.Element(); ok {
		t.Fatal("object became array")
	}
	raw := map[string]any{"x": "first"}
	snapshot, err := element.Admit(raw, "source")
	if err != nil {
		t.Fatal(err)
	}
	raw["x"] = "second"
	if snapshot.(map[string]any)["x"] != "first" {
		t.Fatal("dynamic map snapshot aliases caller")
	}
}

func TestExclusiveSumBooleanLiteralsAndNonNullProjection(t *testing.T) {
	choices := []Shape{StringLiteral("a"), StringLiteral("b")}
	choice := OneOf(choices...)
	choices[0] = String()
	for _, value := range []string{"a", "b"} {
		if _, err := choice.Admit(value, "choice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := choice.Admit("c", "choice"); err == nil {
		t.Fatal("sum retained caller alternative alias")
	}
	ambiguous := OneOf(String(), StringLiteral("a"))
	if _, err := ambiguous.Admit("a", "choice"); err == nil {
		t.Fatal("multiple matching alternatives admitted")
	}
	if _, err := ambiguous.Admit("b", "choice"); err != nil {
		t.Fatal(err)
	}
	nullable := Nullable(String())
	strict := NonNullable(nullable)
	if _, err := nullable.Admit(nil, "nullable"); err != nil {
		t.Fatal("non-null projection mutated its operand")
	}
	if _, err := strict.Admit(nil, "strict"); err == nil {
		t.Fatal("non-null projection admitted null")
	}
	if _, err := OneOf(nullable, Nullable(Boolean())).Admit(nil, "choice"); err == nil {
		t.Fatal("null ambiguity admitted")
	}
	if _, err := Nullable(choice).Admit(nil, "outer"); err != nil {
		t.Fatal(err)
	}
	for _, literal := range []bool{false, true} {
		shape := BooleanLiteral(literal)
		if _, err := shape.Admit(literal, "flag"); err != nil {
			t.Fatal(err)
		}
		if _, err := shape.Admit(!literal, "flag"); err == nil {
			t.Fatal("wrong literal admitted")
		}
		if !reflect.DeepEqual(shape.JSONSchema(), map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "boolean", "const": literal}) {
			t.Fatal("boolean literal schema drift")
		}
	}
	number := OneOf(IntegerMinimum(0), String())
	if err := number.CheckGenerated(1, "generated"); err != nil {
		t.Fatal(err)
	}
	if _, err := number.Admit(1, "caller"); err == nil {
		t.Fatal("sum widened caller numeric representation")
	}
	schema := choice.JSONSchema()
	schema["oneOf"].([]any)[0].(map[string]any)["const"] = "changed"
	if _, err := choice.Admit("a", "choice"); err != nil {
		t.Fatal("schema projection mutated sum")
	}
}

func TestAdmissionSeparatesPresenceNullAndValues(t *testing.T) {
	shape := Object(Required("id", String()), Optional("items", Nullable(Array(String(), 1))))
	for _, tc := range []struct {
		name string
		raw  any
		pass bool
	}{
		{"absent-optional", map[string]any{"id": ""}, true},
		{"null-optional", map[string]any{"id": "x", "items": nil}, true},
		{"present", map[string]any{"id": "x", "items": []any{"a"}}, true},
		{"duplicate-items-left-to-owner", map[string]any{"id": "x", "items": []any{"a", "a"}}, true},
		{"missing-required", map[string]any{}, false},
		{"null-required", map[string]any{"id": nil}, false},
		{"wrong-scalar", map[string]any{"id": true}, false},
		{"unknown", map[string]any{"id": "x", "unknown": nil}, false},
		{"empty", map[string]any{"id": "x", "items": []any{}}, false},
		{"wrong-container", map[string]any{"id": "x", "items": "a"}, false},
		{"wrong-element", map[string]any{"id": "x", "items": []any{json.Number("1")}}, false},
		{"root-array", []any{}, false},
		{"root-null", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := shape.Admit(tc.raw, "input")
			if (err == nil) != tc.pass {
				t.Fatalf("admission class mismatch: %v", err)
			}
			if tc.pass && !reflect.DeepEqual(result, tc.raw) {
				t.Fatal("structural admission normalized values or inserted defaults")
			}
		})
	}
	if _, err := Object(Required("value", Nullable(String()))).Admit(map[string]any{}, "input"); err == nil {
		t.Fatal("required nullable field treated as optional")
	}
	if _, err := Object(Required("value", Nullable(String()))).Admit(map[string]any{"value": nil}, "input"); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionAndProjectionDoNotAlias(t *testing.T) {
	values := map[string]struct{}{"x": {}, "y": {}}
	fields := []Property{Required("items", Array(Object(Required("mode", Enum(values))), 0))}
	shape := Object(fields...)
	fields[0] = Optional("unrelated", String())
	delete(values, "x")
	values["z"] = struct{}{}
	raw := map[string]any{"items": []any{map[string]any{"mode": "x"}}}
	result, err := shape.Admit(raw, "input")
	if err != nil {
		t.Fatal(err)
	}
	owned := result.(map[string]any)["items"].([]any)[0].(map[string]any)
	raw["items"].([]any)[0].(map[string]any)["mode"] = "y"
	if owned["mode"] != "x" {
		t.Fatal("admitted snapshot retained caller map alias")
	}
	owned["mode"] = "z"
	if raw["items"].([]any)[0].(map[string]any)["mode"] != "y" {
		t.Fatal("admitted map mutation reached caller")
	}
	first := shape.JSONSchema()
	enum := func(schema map[string]any) []any {
		return schema["properties"].(map[string]any)["items"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["mode"].(map[string]any)["enum"].([]any)
	}
	enum(first)[0] = "z"
	second := shape.JSONSchema()
	if !reflect.DeepEqual(enum(second), []any{"x", "y"}) {
		t.Fatal("nested schema projection aliases another projection or declaration")
	}
	delete(first, "additionalProperties")
	if shape.JSONSchema()["additionalProperties"] != false {
		t.Fatal("root schema projection aliases another projection")
	}
	if _, err := shape.Admit(map[string]any{"items": []any{map[string]any{"mode": "z"}}}, "input"); err == nil {
		t.Fatal("enum declaration changed through caller aliases")
	}
}

func TestNumberPreservesNativeNumericOwner(t *testing.T) {
	shape := Number()
	for _, token := range []string{"1", "1.0", "1e0", "-0", "9223372036854775808"} {
		raw := json.Number(token)
		got, err := shape.Admit(raw, "number")
		if err != nil || got != raw {
			t.Fatalf("structural admission changed token %q: %v", token, err)
		}
	}
	for _, raw := range []any{nil, 1, 1.0, "1", true, []any{}, map[string]any{}} {
		if _, err := shape.Admit(raw, "number"); err == nil {
			t.Fatal("accepted a non-json.Number representation")
		}
	}
	if !reflect.DeepEqual(shape.JSONSchema(), map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "number"}) {
		t.Fatal("number schema added constraints owned by native numeric admission")
	}
}

func TestExactlyOneCountsPresenceNotTruthiness(t *testing.T) {
	shape := ExactlyOne(Object(Optional("a", Nullable(String())), Optional("b", Nullable(String()))), "a", "b")
	for _, raw := range []map[string]any{{"a": nil}, {"b": ""}} {
		if _, err := shape.Admit(raw, "input"); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []map[string]any{{}, {"a": nil, "b": nil}, {"a": "x", "b": "y"}} {
		if _, err := shape.Admit(raw, "input"); err == nil {
			t.Fatal("invalid alternative membership accepted")
		}
	}
}

func TestIntegerLiteralRetainsLexicalAndInt64Boundary(t *testing.T) {
	shape := IntegerLiteral(1)
	for _, raw := range []any{nil, "1", 1, 1.0, json.Number("1.0"), json.Number("1e0"), json.Number("01"), json.Number("+1"), json.Number("-0"), json.Number("9223372036854775808")} {
		if _, err := shape.Admit(raw, "version"); err == nil {
			t.Fatal("noncanonical or nonmatching integer accepted")
		}
	}
	if _, err := shape.Admit(json.Number("1"), "version"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []int64{-9223372036854775808, 0, 9007199254740993, 9223372036854775807} {
		n := IntegerLiteral(value)
		wire := n.JSONSchema()["const"].(json.Number)
		if _, err := n.Admit(wire, "integer"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProjectionHasExactStructuralConstraints(t *testing.T) {
	shape := ExactlyOne(Object(
		Required("version", IntegerLiteral(1)),
		Optional("a", Nullable(Enum(map[string]struct{}{"y": {}, "x": {}}))),
		Optional("b", Array(String(), 1)),
	), "b", "a")
	encoded, err := json.Marshal(shape.JSONSchema())
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["version"],"properties":{"version":{"type":"integer","const":1,"x-proofkit-number-encoding":"canonical-int64"},"a":{"anyOf":[{"type":"null"},{"type":"string","enum":["x","y"]}]},"b":{"type":"array","minItems":1,"items":{"type":"string"}}},"oneOf":[{"required":["a"]},{"required":["b"]}]}`), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("projection omitted or altered an independently expected clause")
	}
	_, err = Object().Admit(map[string]any{"unknown": "sensitive-private-value"}, "input")
	if err == nil || strings.Contains(err.Error(), "sensitive-private-value") {
		t.Fatal("unknown-field diagnostic leaked caller value")
	}
}

func TestInvalidDeclarationsFailClosed(t *testing.T) {
	if _, err := (Shape{}).Admit(nil, "input"); err == nil {
		t.Fatal("zero shape admitted")
	}
	for _, construct := range []func(){
		func() { Object(Required("x", Shape{})) },
		func() { Object(Required("", String())) },
		func() { Object(Required("x", String()), Optional("x", String())) },
		func() { Array(String(), -1) },
		func() { Enum(nil) },
		func() { Nullable(Shape{}) },
		func() { ExactlyOne(String(), "a", "b") },
		func() { ExactlyOne(Object(Optional("a", String())), "a", "a") },
		func() { ExactlyOne(Object(Required("a", String()), Optional("b", String())), "a", "b") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid trusted declaration was not rejected")
				}
			}()
			construct()
		}()
	}
}
