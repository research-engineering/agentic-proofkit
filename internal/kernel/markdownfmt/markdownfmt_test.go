package markdownfmt

import (
	"strings"
	"testing"
)

func TestTextNeutralizesMarkdownStructure(t *testing.T) {
	got := Text("safe\n# forged\n- item\n![x](https://example.test/x)\n| a | b |\n<script>alert(1)</script>")
	for _, forbidden := range []string{"\n# forged", "\n- item", "![x](", "| a | b |", "<script>"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("Text() preserved structural markdown/html token %q in %q", forbidden, got)
		}
	}
	for _, required := range []string{`\# forged`, `\- item`, `\!\[x\]\(https://example\.test/x\)`, `\| a \| b \|`, `&lt;script&gt;`} {
		if !strings.Contains(got, required) {
			t.Fatalf("Text() missing escaped token %q in %q", required, got)
		}
	}
}

func TestCodeSpanUsesDelimiterLongerThanContentBacktickRuns(t *testing.T) {
	for value, want := range map[string]string{
		"a`b":    "``a`b``",
		"a``b`c": "```a``b`c```",
	} {
		if got := CodeSpan(value); got != want {
			t.Fatalf("CodeSpan(%q) = %q, want %q", value, got, want)
		}
	}
}

// CommonMark strips one space from each side of code-span content that begins
// and ends with a space; padding keeps edge backticks out of the delimiters.
func TestCodeSpanPadsEdgeBackticksAndSpaces(t *testing.T) {
	for value, want := range map[string]string{
		"name`":  "`` name` ``",
		"`lead":  "`` `lead ``",
		"`":      "`` ` ``",
		" a ":    "`  a  `",
		" a":     "` a`",
		"   ":    "`   `",
		"a\r\nb": "`a b`",
		"a\n\nb": "`a  b`",
	} {
		if got := CodeSpan(value); got != want {
			t.Fatalf("CodeSpan(%q) = %q, want %q", value, got, want)
		}
	}
}

// Code spans cannot escape '<', '>' or '&'; those payloads render as escaped
// inline text whose entities decode to the original characters.
func TestCodeSpanRendersHTMLSensitivePayloadAsEscapedText(t *testing.T) {
	for value, want := range map[string]string{
		"a&b":                            "a&amp;b",
		"go test ./... && npm run check": "go test \\./\\.\\.\\. &amp;&amp; npm run check",
		"docs/specs/x`<img src=x onerror=alert(1)>`": "docs/specs/x\\`&lt;img src=x onerror=alert\\(1\\)&gt;\\`",
		"&amp;amp;": "&amp;amp;amp;",
		" a&b\t":    "&#32;a&amp;b&#9;",
		"~~~ a&b":   "\\~\\~\\~ a&amp;b",
		"a&b\n# c":  "a&amp;b \\# c",
		"":          "",
	} {
		got := CodeSpan(value)
		if got != want {
			t.Fatalf("CodeSpan(%q) = %q, want %q", value, got, want)
		}
		if strings.ContainsAny(got, "<>\n") {
			t.Fatalf("CodeSpan(%q) = %q emits raw angle brackets or line endings", value, got)
		}
	}
}

func TestCodeListOrNone(t *testing.T) {
	if got := CodeListOrNone(nil); got != "none" {
		t.Fatalf("CodeListOrNone(nil) = %q", got)
	}
	if got := CodeListOrNone([]string{"a", "b"}); got != "`a`, `b`" {
		t.Fatalf("CodeListOrNone() = %q", got)
	}
	if got := CodeListOrNone([]string{"a&b", "c`"}); got != "a&amp;b, `` c` ``" {
		t.Fatalf("CodeListOrNone() = %q", got)
	}
}
