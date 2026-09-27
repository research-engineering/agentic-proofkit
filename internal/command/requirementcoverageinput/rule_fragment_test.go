package requirementcoverageinput

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestRuleFragmentClassifiesDecodedFirstScalar(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"", "id_"}, {"123", "id_123"}, {"A.B-C", "a_b_c"},
		{"\u0661name", "id_\u0661name"}, {"\u03b1name", "\u03b1name"},
	} {
		if got := ruleFragment(test.input); got != test.want {
			t.Fatalf("fragment %q = %q, want %q", test.input, got, test.want)
		}
	}
	// Non-ASCII examples exercise the helper, not publicly admitted owner IDs.
	if _, err := admit.RuleID("\u0661name", "owner"); err == nil {
		t.Fatal("non-ASCII owner unexpectedly admitted")
	}
	for _, owner := range []string{"project.api", "A.B-C", "x:9_y"} {
		if _, err := admit.RuleID(owner, "owner"); err != nil {
			t.Fatal(err)
		}
		if _, err := admit.RuleID(observedTestSurfaceID(owner, "tests/example.go"), "surface"); err != nil {
			t.Fatalf("admitted owner lost stable generated identity: %v", err)
		}
	}
}
