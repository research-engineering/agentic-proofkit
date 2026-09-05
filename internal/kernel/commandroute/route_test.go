package commandroute

import (
	"slices"
	"testing"
)

func TestGrammarBoundariesAreExact(t *testing.T) {
	if OmittedRoutePolicy != "command_id" {
		t.Fatalf("omitted route policy=%q", OmittedRoutePolicy)
	}
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

func TestOmittedRoutePolicyUsesStableCommandIdentity(t *testing.T) {
	if OmittedRoutePolicy != "command_id" {
		t.Fatalf("omitted route policy=%q, want command_id", OmittedRoutePolicy)
	}
	omitted, ok := Resolve("stable-command", nil)
	if !ok || !slices.Equal(omitted, []string{"stable-command"}) {
		t.Fatalf("omitted route resolved to %v, ok=%v", omitted, ok)
	}
	explicitInput := []string{"stable", "route"}
	explicit, ok := Resolve("stable-command", explicitInput)
	if !ok || !slices.Equal(explicit, explicitInput) {
		t.Fatalf("explicit route resolved to %v, ok=%v", explicit, ok)
	}
	explicit[0] = "changed"
	if explicitInput[0] != "stable" {
		t.Fatal("resolved route aliases caller-owned input")
	}
	for _, test := range []struct {
		commandID string
		route     []string
	}{
		{commandID: "invalid command", route: nil},
		{commandID: "stable-command", route: []string{}},
		{commandID: "stable-command", route: []string{"Invalid"}},
	} {
		if resolved, valid := Resolve(test.commandID, test.route); valid || resolved != nil {
			t.Fatalf("Resolve(%q, %v)=%v, %v; want nil, false", test.commandID, test.route, resolved, valid)
		}
	}
}
