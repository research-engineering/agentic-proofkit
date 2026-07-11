package admission

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsExcessiveNestingDepth(t *testing.T) {
	cases := []struct {
		name  string
		input string
		valid bool
	}{
		{name: "array at limit", input: strings.Repeat("[", maxJSONNestingDepth-1) + "0" + strings.Repeat("]", maxJSONNestingDepth-1), valid: true},
		{name: "array beyond limit", input: strings.Repeat("[", maxJSONNestingDepth) + "0" + strings.Repeat("]", maxJSONNestingDepth), valid: false},
		{name: "object at limit", input: strings.Repeat(`{"v":`, maxJSONNestingDepth-1) + "0" + strings.Repeat("}", maxJSONNestingDepth-1), valid: true},
		{name: "object beyond limit", input: strings.Repeat(`{"v":`, maxJSONNestingDepth) + "0" + strings.Repeat("}", maxJSONNestingDepth), valid: false},
		{name: "mixed beyond limit", input: strings.Repeat(`[{"v":`, maxJSONNestingDepth/2) + "0" + strings.Repeat("}]", maxJSONNestingDepth/2), valid: false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := DecodeJSON(strings.NewReader(item.input), int64(len(item.input)))
			if item.valid && err != nil {
				t.Fatalf("DecodeJSON() valid boundary error=%v", err)
			}
			if !item.valid && (err == nil || !strings.Contains(err.Error(), "nesting depth limit")) {
				t.Fatalf("DecodeJSON() error=%v, want bounded nesting rejection", err)
			}
		})
	}
}

func TestDecodeJSONRejectsDuplicateKeysWithoutEchoingKey(t *testing.T) {
	_, err := DecodeJSON(strings.NewReader(`{"token": 1, "token": 2}`), 1024)
	if err == nil {
		t.Fatal("expected duplicate key rejection")
	}
	if !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "token") {
		t.Fatalf("duplicate key error must not echo key material: %v", err)
	}
}

func TestDecodeJSONRejectsMalformedInputCorpus(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "nested duplicate key", input: `{"outer":{"token":1,"token":2}}`, want: "duplicate object key"},
		{name: "escaped duplicate key", input: `{"token":1,"\u0074oken":2}`, want: "duplicate object key"},
		{name: "multiple values", input: `{"ok":true} {"extra":true}`, want: "multiple JSON values"},
		{name: "trailing array value", input: `[1] false`, want: "multiple JSON values"},
		{name: "object missing colon", input: `{"ok" true}`, want: "colon"},
		{name: "array missing comma", input: `[1 2]`, want: "array values must be separated by comma"},
		{name: "invalid number", input: `{"n":01}`, want: "invalid JSON input"},
		{name: "invalid literal", input: `{"ok":truth}`, want: "unexpected token"},
		{name: "unterminated string", input: `{"ok":"value}`, want: "unterminated string"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := DecodeJSON(strings.NewReader(item.input), 1024)
			if err == nil {
				t.Fatal("expected malformed JSON rejection")
			}
			if !strings.Contains(err.Error(), item.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), item.want)
			}
		})
	}
}

func TestDecodeJSONRejectsResourceLimit(t *testing.T) {
	_, err := DecodeJSON(strings.NewReader(`{"value":"abcdef"}`), 8)
	if err == nil {
		t.Fatal("expected resource limit rejection")
	}
	if !strings.Contains(err.Error(), "resource limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeJSONAcceptsNestedObjects(t *testing.T) {
	value, err := DecodeJSON(strings.NewReader(`{"items":[{"a":1},{"a":2}],"ok":true}`), 1024)
	if err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatalf("expected object value, got %T", value)
	}
}

func TestDecodeTypedJSONUsesStrictAdmission(t *testing.T) {
	type record struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	_, err := DecodeTypedJSON[record](strings.NewReader(`{"schemaVersion":1,"schemaVersion":2}`), 1024)
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("DecodeTypedJSON() error = %v, want duplicate-key rejection", err)
	}

	out, err := DecodeTypedJSON[record](strings.NewReader(`{"schemaVersion":1}`), 1024)
	if err != nil {
		t.Fatalf("DecodeTypedJSON() valid input error = %v", err)
	}
	if out.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion=%d want 1", out.SchemaVersion)
	}

	var raw map[string]json.Number
	if raw, err = DecodeTypedJSON[map[string]json.Number](strings.NewReader(`{"n":123}`), 1024); err != nil {
		t.Fatalf("DecodeTypedJSON() number input error = %v", err)
	}
	if raw["n"] != json.Number("123") {
		t.Fatalf("n=%v want 123", raw["n"])
	}
}
