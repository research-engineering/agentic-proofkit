package admission

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestDecodeJSONRejectsLossyUnicodeInputs(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "invalid UTF-8 ff", input: []byte{'{', '"', 'v', '"', ':', '"', 0xff, '"', '}'}},
		{name: "invalid UTF-8 fe", input: []byte{'{', '"', 'v', '"', ':', '"', 0xfe, '"', '}'}},
		{name: "unpaired high surrogate", input: []byte(`{"v":"\ud800"}`)},
		{name: "unpaired low surrogate", input: []byte(`{"v":"\udc00"}`)},
		{name: "high surrogate followed by non-low surrogate", input: []byte(`{"v":"\ud800\u0041"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeJSON(bytes.NewReader(test.input), 1024); err == nil {
				t.Fatal("DecodeJSON accepted a lossy Unicode input")
			}
		})
	}
}

func TestDecodeJSONAcceptsUnicodeScalarValues(t *testing.T) {
	for _, input := range []string{
		`{"literal":"` + string('\ufffd') + `"}`,
		`{"escaped":"\ufffd"}`,
		`{"pair":"\ud83d\ude80"}`,
	} {
		if _, err := DecodeJSON(strings.NewReader(input), 1024); err != nil {
			t.Fatalf("DecodeJSON(%q) error=%v", input, err)
		}
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
		Metadata      map[string]any `json:"metadata"`
		SchemaVersion int            `json:"schemaVersion"`
		Version       string         `json:"version"`
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

	if _, err := DecodeTypedJSON[record](strings.NewReader(`{"schemaVersion":1,"VERSION":"9.9.9"}`), 1024); err == nil || !strings.Contains(err.Error(), "exact declared field") {
		t.Fatalf("DecodeTypedJSON() case-folded key error = %v, want exact-key rejection", err)
	}

	large, err := DecodeTypedJSON[record](strings.NewReader(`{"schemaVersion":1,"metadata":{"n":10000000000000000000}}`), 1024)
	if err != nil {
		t.Fatalf("DecodeTypedJSON() large number error = %v", err)
	}
	if number, ok := large.Metadata["n"].(json.Number); !ok || number.String() != "10000000000000000000" {
		t.Fatalf("metadata.n=%#v, want exact json.Number", large.Metadata["n"])
	}
}

func TestSyntaxErrorKeepsMessageAndLocatesRejectedByte(t *testing.T) {
	cases := []struct {
		name, input, message string
		offset, line, column int
	}{
		{name: "duplicate key selects the repeated key", input: `{"x":1,"x":2}`, message: "invalid JSON input: duplicate object key", offset: 7, line: 1, column: 8},
		{name: "unterminated object ends at input length", input: "{", message: "invalid JSON input: unterminated object", offset: 1, line: 1, column: 2},
		{name: "empty input", input: "", message: "invalid JSON input: unexpected end", offset: 0, line: 1, column: 1},
		{name: "second value", input: "{} {}", message: "invalid JSON input: multiple JSON values", offset: 3, line: 1, column: 4},
		{name: "multi-byte line counts scalar columns", input: "{\n  \"\u00e9\u20ac\U0001F600\": [1 2]\n}", message: "invalid JSON input: array values must be separated by comma", offset: 20, line: 2, column: 13},
		{name: "CRLF ends one line", input: "{\r\n\"a\":1,\r\n7}", message: "invalid JSON input: object key must be a string", offset: 11, line: 3, column: 1},
		{name: "bare CR ends one line", input: "[1,\rtruth]", message: "invalid JSON input: unexpected token", offset: 4, line: 2, column: 1},
		{name: "standard decoder rejection", input: "{\"n\":01}", message: "invalid JSON input: invalid character '1' after object key:value pair", offset: 6, line: 1, column: 7},
		{name: "invalid UTF-8 byte after scalars", input: "[\"\u00e9\xff\"]", message: "invalid JSON input: source must be valid UTF-8", offset: 4, line: 1, column: 4},
		{name: "invalid escape selects the escaped byte", input: `["bad\q"]`, message: "invalid JSON input: invalid string token", offset: 6, line: 1, column: 7},
		{name: "invalid escape after a multi-byte scalar", input: "[\"\u00e9\\q\"]", message: "invalid JSON input: invalid string token", offset: 5, line: 1, column: 5},
		{name: "invalid escape in an object key", input: `{"a\q":1}`, message: "invalid JSON input: invalid string token", offset: 4, line: 1, column: 5},
		{name: "raw control character in a string", input: "[\"a\tb\"]", message: "invalid JSON input: invalid string token", offset: 3, line: 1, column: 4},
		{name: "unpaired high surrogate selects its escape", input: `["ok\ud800x"]`, message: "invalid JSON input: unpaired Unicode surrogate", offset: 4, line: 1, column: 5},
		{name: "high surrogate followed by a non-surrogate escape", input: `["\ud800\u0041"]`, message: "invalid JSON input: unpaired Unicode surrogate", offset: 2, line: 1, column: 3},
		{name: "lone low surrogate selects its escape", input: `["a","b\udc00"]`, message: "invalid JSON input: unpaired Unicode surrogate", offset: 7, line: 1, column: 8},
		{name: "nesting depth selects the value past the limit, not the whitespace before it", input: strings.Repeat(`{"a": `, 512) + "1" + strings.Repeat("}", 512), message: "invalid JSON input: exceeds nesting depth limit", offset: 3072, line: 1, column: 3073},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := DecodeJSON(strings.NewReader(item.input), 1<<16)
			var syntax *SyntaxError
			if !errors.As(err, &syntax) {
				t.Fatalf("DecodeJSON() error = %T %v, want *SyntaxError", err, err)
			}
			if err.Error() != item.message {
				t.Fatalf("Error() = %q, want the unchanged message %q", err.Error(), item.message)
			}
			if syntax.Offset != item.offset || syntax.Line != item.line || syntax.Column != item.column {
				t.Fatalf("position = byte %d line %d column %d, want byte %d line %d column %d", syntax.Offset, syntax.Line, syntax.Column, item.offset, item.line, item.column)
			}
		})
	}
	if _, err := DecodeJSON(strings.NewReader(`{"a":1}`), 3); err == nil || errors.As(err, new(*SyntaxError)) {
		t.Fatalf("resource limit error = %v, want an unlocated non-syntax rejection", err)
	}
}
