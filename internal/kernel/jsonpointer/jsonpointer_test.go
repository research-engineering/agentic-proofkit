package jsonpointer

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectRFC6901Pointers(t *testing.T) {
	input := map[string]any{
		"envelope": map[string]any{
			"input": []any{
				map[string]any{"value": "first"},
				map[string]any{"value": "second"},
			},
		},
		"a/b": "slash",
		"a~b": "tilde",
	}
	for _, test := range []struct {
		name    string
		pointer string
		want    any
	}{
		{name: "root", pointer: "", want: input},
		{name: "nested", pointer: "/envelope/input/1/value", want: "second"},
		{name: "slash escape", pointer: "/a~1b", want: "slash"},
		{name: "tilde escape", pointer: "/a~0b", want: "tilde"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Select(input, test.pointer)
			if err != nil {
				t.Fatalf("Select returned error: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestParseAndSelectParsedPreserveSelectionSemantics(t *testing.T) {
	input := map[string]any{"a/b": []any{map[string]any{"a~b": "selected"}}}
	pointer, err := Parse("/a~1b/0/a~0b")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	got, err := SelectParsed(input, pointer)
	if err != nil {
		t.Fatalf("SelectParsed returned error: %v", err)
	}
	if got != "selected" {
		t.Fatalf("SelectParsed returned %v, want selected", got)
	}
}

func TestParseRejectsInvalidSyntaxWithoutDocumentAccess(t *testing.T) {
	for _, value := range []string{"not-a-pointer", "/bad~", "/bad~2escape"} {
		t.Run(value, func(t *testing.T) {
			if _, err := Parse(value); err == nil {
				t.Fatal("expected syntax error")
			}
		})
	}
}

func TestSelectRejectsInvalidPointers(t *testing.T) {
	input := map[string]any{"items": []any{"first"}}
	for _, pointer := range []string{
		"items/0",
		"/items/01",
		"/items/x",
		"/items/1",
		"/missing",
		"/items/0/missing",
		"/a~2b",
		"/a~",
	} {
		t.Run(pointer, func(t *testing.T) {
			if _, err := Select(input, pointer); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestSelectRedactsCallerControlledDiagnostics(t *testing.T) {
	input := map[string]any{"items": []any{"first"}}
	secret := "ghp_FAKEFAKE1234567890"
	for _, pointer := range []string{
		"/" + secret,
		"/items/" + secret,
		"/items/https:~1~1user:pass@example.test",
		"/items/bad\nsegment",
		"/bad~" + secret,
	} {
		t.Run(pointer, func(t *testing.T) {
			_, err := Select(input, pointer)
			if err == nil {
				t.Fatalf("expected error")
			}
			message := err.Error()
			for _, forbidden := range []string{secret, "user:pass", "\n"} {
				if strings.Contains(message, forbidden) {
					t.Fatalf("diagnostic leaked %q in %q", forbidden, message)
				}
			}
		})
	}
}
