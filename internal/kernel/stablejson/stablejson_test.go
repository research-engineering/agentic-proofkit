package stablejson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMarshalSortsObjectKeys(t *testing.T) {
	output, err := Marshal(map[string]any{
		"z": "last",
		"a": []any{"first", true},
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	const expected = "{\n  \"a\": [\n    \"first\",\n    true\n  ],\n  \"z\": \"last\"\n}\n"
	if string(output) != expected {
		t.Fatalf("unexpected stable JSON:\n%s", output)
	}
}

func TestMarshalLayoutCompactPreservesSortedJSONValue(t *testing.T) {
	value := map[string]any{"z": "last", "a": []any{"first", true}}
	pretty, err := MarshalLayout(value, LayoutPretty)
	if err != nil {
		t.Fatalf("marshal pretty failed: %v", err)
	}
	compact, err := MarshalLayout(value, LayoutCompact)
	if err != nil {
		t.Fatalf("marshal compact failed: %v", err)
	}
	if got, want := string(compact), "{\"a\":[\"first\",true],\"z\":\"last\"}\n"; got != want {
		t.Fatalf("compact output = %q, want %q", got, want)
	}
	var prettyValue any
	var compactValue any
	if err := json.Unmarshal(pretty, &prettyValue); err != nil {
		t.Fatalf("decode pretty output: %v", err)
	}
	if err := json.Unmarshal(compact, &compactValue); err != nil {
		t.Fatalf("decode compact output: %v", err)
	}
	if fmt.Sprint(prettyValue) != fmt.Sprint(compactValue) {
		t.Fatalf("layout changed JSON value: pretty=%v compact=%v", prettyValue, compactValue)
	}
}

func TestMarshalLayoutRejectsUnknownLayout(t *testing.T) {
	if _, err := MarshalLayout(map[string]any{}, Layout("dense")); err == nil {
		t.Fatal("MarshalLayout accepted an unknown layout")
	}
}

func TestMarshalRejectsNonNumberJSONNumberTokens(t *testing.T) {
	for _, value := range []json.Number{
		"true",
		"null",
		"{}",
		"[]",
		`"1"`,
		"01",
		"+1",
		"1.",
		"NaN",
	} {
		t.Run(value.String(), func(t *testing.T) {
			if _, err := Marshal(map[string]any{"value": value}); err == nil {
				t.Fatalf("Marshal accepted invalid JSON number token %q", value.String())
			}
		})
	}
}

func TestMarshalAcceptsJSONNumberGrammar(t *testing.T) {
	for _, value := range []json.Number{"0", "-0", "12", "-12.5", "1e9", "1E-9"} {
		t.Run(value.String(), func(t *testing.T) {
			if _, err := Marshal(map[string]any{"value": value}); err != nil {
				t.Fatalf("Marshal rejected valid JSON number token %q: %v", value.String(), err)
			}
		})
	}
}

func TestQuoteFastPathMatchesCanonicalEncoder(t *testing.T) {
	for _, value := range []string{
		"",
		"plain ASCII",
		"<html>&text",
		"quote\"slash\\",
		"line\nbreak",
		"cafe\u0301",
		"\u2028\u2029",
	} {
		var buffer strings.Builder
		if err := writeValue(&buffer, value, 0, LayoutCompact); err != nil {
			t.Fatalf("writeValue(%q): %v", value, err)
		}
		var reference bytes.Buffer
		encoder := json.NewEncoder(&reference)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			t.Fatalf("encode reference %q: %v", value, err)
		}
		want := strings.TrimSuffix(reference.String(), "\n")
		if buffer.String() != want {
			t.Fatalf("quote(%q)=%q want %q", value, buffer.String(), want)
		}
	}
}

func TestMarshalRejectsMalformedUTF8(t *testing.T) {
	for _, value := range []string{
		string([]byte{0xff}),
		string([]byte{0xc3, 0x28}),
		string([]byte{0xed, 0xa0, 0x80}),
	} {
		if _, err := Marshal(map[string]any{"value": value}); err == nil {
			t.Fatalf("Marshal accepted malformed UTF-8 %x", []byte(value))
		}
		if _, err := Marshal(map[string]any{value: "key"}); err == nil {
			t.Fatalf("Marshal accepted malformed UTF-8 key %x", []byte(value))
		}
	}
}

func TestMarshalEscapesUnsafeUnicodeAndPreservesScalarOrder(t *testing.T) {
	value := map[string]any{
		"value":      "\u007f\u0085\u200b\u2028\u2029\U000e0001",
		"\U00010000": "supplementary",
		"\ue000":     "bmp",
	}
	output, err := MarshalLayout(value, LayoutCompact)
	if err != nil {
		t.Fatalf("MarshalLayout failed: %v", err)
	}
	const expected = "{\"value\":\"\\u007f\\u0085\\u200b\\u2028\\u2029\\udb40\\udc01\",\"\ue000\":\"bmp\",\"\U00010000\":\"supplementary\"}\n"
	if string(output) != expected {
		t.Fatalf("compact output = %q, want %q", output, expected)
	}
}

func TestUnicodePolicyCorpus(t *testing.T) {
	valueCases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "ascii", value: "alpha", want: "{\"value\":\"alpha\"}\n"},
		{name: "html", value: "<&>", want: "{\"value\":\"<&>\"}\n"},
		{name: "emoji", value: "\U0001f600", want: "{\"value\":\"\U0001f600\"}\n"},
		{name: "combining", value: "e\u0301", want: "{\"value\":\"e\u0301\"}\n"},
		{name: "short_controls", value: "\b\t\n\f\r", want: "{\"value\":\"\\b\\t\\n\\f\\r\"}\n"},
		{name: "c0_nul", value: "\x00", want: "{\"value\":\"\\u0000\"}\n"},
		{name: "del", value: "\x7f", want: "{\"value\":\"\\u007f\"}\n"},
		{name: "c1_next_line", value: "\u0085", want: "{\"value\":\"\\u0085\"}\n"},
		{name: "cf_zero_width_space", value: "\u200b", want: "{\"value\":\"\\u200b\"}\n"},
		{name: "cf_supplementary_language_tag", value: "\U000e0001", want: "{\"value\":\"\\udb40\\udc01\"}\n"},
		{name: "line_separator", value: "\u2028", want: "{\"value\":\"\\u2028\"}\n"},
		{name: "paragraph_separator", value: "\u2029", want: "{\"value\":\"\\u2029\"}\n"},
	}
	for _, test := range valueCases {
		t.Run(test.name, func(t *testing.T) {
			output, err := MarshalLayout(map[string]any{"value": test.value}, LayoutCompact)
			if err != nil {
				t.Fatalf("MarshalLayout failed: %v", err)
			}
			if got := string(output); got != test.want {
				t.Fatalf("compact output = %q, want %q", got, test.want)
			}
			var decoded map[string]string
			if err := json.Unmarshal(output, &decoded); err != nil {
				t.Fatalf("decode output: %v", err)
			}
			if got := decoded["value"]; got != test.value {
				t.Fatalf("decoded value = %q, want %q", got, test.value)
			}
		})
	}

	keyCases := []struct {
		name  string
		value map[string]any
		want  string
	}{
		{name: "cf_key", value: map[string]any{"\u200b": "value"}, want: "{\"\\u200b\":\"value\"}\n"},
		{
			name:  "bmp_before_supplementary_scalar_order",
			value: map[string]any{"\U00010000": "supplementary", "\ue000": "bmp"},
			want:  "{\"\ue000\":\"bmp\",\"\U00010000\":\"supplementary\"}\n",
		},
	}
	for _, test := range keyCases {
		t.Run(test.name, func(t *testing.T) {
			output, err := MarshalLayout(test.value, LayoutCompact)
			if err != nil {
				t.Fatalf("MarshalLayout failed: %v", err)
			}
			if got := string(output); got != test.want {
				t.Fatalf("compact output = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMarshalRejectsEveryMalformedUTF8Class(t *testing.T) {
	malformed := []struct {
		name  string
		value []byte
	}{
		{name: "isolated_continuation", value: []byte{0x80}},
		{name: "invalid_lead", value: []byte{0xff}},
		{name: "overlong", value: []byte{0xc0, 0x80}},
		{name: "truncated", value: []byte{0xe2, 0x82}},
		{name: "surrogate", value: []byte{0xed, 0xa0, 0x80}},
		{name: "out_of_range", value: []byte{0xf4, 0x90, 0x80, 0x80}},
	}
	for _, test := range malformed {
		t.Run(test.name, func(t *testing.T) {
			value := string(test.value)
			if _, err := MarshalLayout(map[string]any{"value": value}, LayoutCompact); err == nil {
				t.Fatal("MarshalLayout accepted malformed UTF-8 value")
			}
			if _, err := MarshalLayout(map[string]any{value: true}, LayoutCompact); err == nil {
				t.Fatal("MarshalLayout accepted malformed UTF-8 key")
			}
		})
	}
}
