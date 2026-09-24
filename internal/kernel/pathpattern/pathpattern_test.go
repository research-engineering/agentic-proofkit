package pathpattern

import "testing"

func TestMatchAdmitsRepoRelativeGlobSemantics(t *testing.T) {
	cases := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"docs", "docs/a.md", true},
		{"docs/*.md", "docs/a.md", true},
		{"docs/*.md", "docs/nested/a.md", false},
		{"docs/**/*.md", "docs/a.md", true},
		{"docs/**/*.md", "docs/nested/a.md", true},
		{"docs/a.md", "docs/a.md", true},
		{"docs/a.md", "docs/b.md", false},
		{"docs/\u00e9*", "docs/\u00e9clair.md", true},
		{"docs/\u00e9*", "docs/eclair.md", false},
		{"docs/e\u0301*", "docs/e\u0301clair.md", true},
		{"docs/\U0001f4c4/**/*.md", "docs/\U0001f4c4/a.md", true},
		{"docs/\U0001f4c4/**/*.md", "docs/\U0001f4c4/nested/a.md", true},
		{"docs/[\u00e9]+*.md", "docs/[\u00e9]+one.md", true},
		{"docs/[\u00e9]+*.md", "docs/eone.md", false},
		{"../docs/*.md", "docs/a.md", false},
		{"docs/*.md", "../docs/a.md", false},
	}

	for _, tc := range cases {
		if got := Match(tc.pattern, tc.target); got != tc.want {
			t.Fatalf("Match(%q, %q)=%v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

func BenchmarkCompiledMatchAdmitted(b *testing.B) {
	pattern, err := Compile("docs/\u00e9/**/*.md", "benchmark pattern")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if !pattern.MatchAdmitted("docs/\u00e9/nested/page.md") {
			b.Fatal("admitted Unicode path did not match")
		}
	}
}

func TestMatchAnyAndValidateShareOwnerSemantics(t *testing.T) {
	if err := Validate("docs/**/*.md", "test path pattern"); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := Validate("../docs/**/*.md", "test path pattern"); err == nil {
		t.Fatalf("Validate() accepted escaping pattern")
	}
	if !MatchAny([]string{"docs/*.md", "proofkit/**/*.json"}, "proofkit/cli-contract.v2.json") {
		t.Fatalf("MatchAny() did not match proofkit contract")
	}
	if MatchAny([]string{"docs/*.md"}, "src/main.go") {
		t.Fatalf("MatchAny() matched unrelated path")
	}
}

func TestCompileRejectsInvalidUTF8(t *testing.T) {
	for _, pattern := range []string{"docs/\xff", "docs/\xff*"} {
		if _, err := Compile(pattern, "test pattern"); err == nil {
			t.Fatal("Compile admitted invalid UTF-8")
		}
	}
}

func TestCompiledPatternsPreserveMatcherSemanticsAcrossRepeatedTargets(t *testing.T) {
	compiled, err := Compile("docs/**/*.md", "test pattern")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	for _, item := range []struct {
		target string
		want   bool
	}{
		{target: "docs/a.md", want: true},
		{target: "docs/nested/a.md", want: true},
		{target: "docs/a.go", want: false},
	} {
		if got := compiled.MatchAdmitted(item.target); got != item.want {
			t.Fatalf("compiled.MatchAdmitted(%q)=%v, want %v", item.target, got, item.want)
		}
		if got := Match(compiled.String(), item.target); got != item.want {
			t.Fatalf("Match(%q, %q)=%v, want %v", compiled.String(), item.target, got, item.want)
		}
	}
}
