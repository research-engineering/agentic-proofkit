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
		{"../docs/*.md", "docs/a.md", false},
		{"docs/*.md", "../docs/a.md", false},
	}

	for _, tc := range cases {
		if got := Match(tc.pattern, tc.target); got != tc.want {
			t.Fatalf("Match(%q, %q)=%v, want %v", tc.pattern, tc.target, got, tc.want)
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
	if !MatchAny([]string{"docs/*.md", "proofkit/**/*.json"}, "proofkit/cli-contract.v1.json") {
		t.Fatalf("MatchAny() did not match proofkit contract")
	}
	if MatchAny([]string{"docs/*.md"}, "src/main.go") {
		t.Fatalf("MatchAny() matched unrelated path")
	}
}
