package jsonshape

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNonBlankStringUsesNativeWhitespaceInventory(t *testing.T) {
	shape := NonBlankString()
	for _, value := range []string{"", " \t\r\n", "\u0085", "\u00a0\u1680\u2000\u2028\u202f\u205f\u3000", "x", "\u0085x\u0085", "\ufeff", "\x00"} {
		_, err := shape.Admit(value, "text")
		if (err == nil) != (strings.TrimSpace(value) != "") {
			t.Fatalf("nonblank admission disagrees with native whitespace: %q", value)
		}
	}
	for _, value := range []any{nil, true, 1, []any{}} {
		if _, err := shape.Admit(value, "text"); err == nil {
			t.Fatal("nonblank shape accepted a non-string")
		}
	}
	var escaped strings.Builder
	for _, value := range trimSpaceCharacters() {
		if strings.TrimSpace(string(value)) != "" {
			t.Fatal("projected whitespace is not native whitespace")
		}
		fmt.Fprintf(&escaped, `\u%04x`, value)
	}
	if escaped.String() != TrimSpacePatternClass() {
		t.Fatal("ECMAScript and Go whitespace projections differ")
	}
	for _, r := range shape.JSONSchema()["pattern"].(string) {
		if r >= utf8.RuneSelf {
			t.Fatal("schema grammar contains non-ASCII source instead of escaped Unicode")
		}
	}
}
