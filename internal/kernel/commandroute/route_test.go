package commandroute

import (
	"slices"
	"testing"
)

func TestGrammarBoundariesAreExact(t *testing.T) {
	valid := []string{"one", "two", "three", "four"}
	if !Valid(valid[:MinimumTokens]) || !Valid(valid[:MaximumTokens]) {
		t.Fatal("exact command-route token bounds were rejected")
	}
	if Valid(nil) || Valid(append(valid, "five")) {
		t.Fatal("command-route values outside exact token bounds were accepted")
	}
	for _, token := range []string{"a", "0", "a0", "a-b", "0-9"} {
		if !ValidToken(token) {
			t.Fatalf("valid command-route token %q was rejected", token)
		}
	}
	for _, token := range []string{"", "-leading", "trailing-", "double--hyphen", "Upper", "under_score"} {
		if ValidToken(token) {
			t.Fatalf("invalid command-route token %q was accepted", token)
		}
	}
}

func TestParseRequiresCanonicalSeparatorAndRoundTrip(t *testing.T) {
	want := []string{"adopt", "plan"}
	got, ok := Parse("adopt plan")
	if !ok || !slices.Equal(got, want) || Text(got) != "adopt plan" {
		t.Fatalf("Parse()=%v,%v, want exact round trip %v", got, ok, want)
	}
	for _, mutant := range []string{"", "adopt  plan", " adopt plan", "adopt plan ", "adopt\tplan"} {
		if _, ok := Parse(mutant); ok {
			t.Fatalf("non-canonical command route %q was accepted", mutant)
		}
	}
}

func TestPrefixIsStrict(t *testing.T) {
	if !Prefix([]string{"adopt"}, []string{"adopt", "plan"}) {
		t.Fatal("strict route prefix was not recognized")
	}
	if Prefix([]string{"adopt"}, []string{"adopt"}) || Prefix([]string{"plan"}, []string{"adopt", "plan"}) {
		t.Fatal("non-prefix route was recognized")
	}
}
