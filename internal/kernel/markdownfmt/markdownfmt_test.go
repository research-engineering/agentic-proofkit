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
	got := CodeSpan("docs/specs/x`<img src=x onerror=alert(1)>`")
	want := "``docs/specs/x`&lt;img src=x onerror=alert(1)&gt;```"
	if got != want {
		t.Fatalf("CodeSpan() = %q, want %q", got, want)
	}
}

func TestCodeListOrNone(t *testing.T) {
	if got := CodeListOrNone(nil); got != "none" {
		t.Fatalf("CodeListOrNone(nil) = %q", got)
	}
	if got := CodeListOrNone([]string{"a", "b"}); got != "`a`, `b`" {
		t.Fatalf("CodeListOrNone() = %q", got)
	}
}
