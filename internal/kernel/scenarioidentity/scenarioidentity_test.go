package scenarioidentity

import (
	"strings"
	"testing"
)

func TestAdmitScopedRequiresOneCanonicalSurfaceAndAnchor(t *testing.T) {
	for _, item := range []struct {
		value string
		valid bool
	}{
		{"proofkit.test.surface::scenario_one", true},
		{"scenario.one", false}, {"surface::", false}, {"::anchor", false},
		{"surface::anchor::extra", false}, {"surface::bad value", false},
	} {
		actual, surface, err := AdmitScoped(item.value, "scenario")
		if (err == nil) != item.valid {
			t.Fatalf("%q: error=%v, want valid=%t", item.value, err, item.valid)
		}
		if item.valid && (actual != item.value || surface != "proofkit.test.surface") {
			t.Fatalf("%q changed canonical identity", item.value)
		}
	}
}

func TestAdmitSourceIDUsesOnlyGenericOrScopedGrammar(t *testing.T) {
	for _, item := range []struct {
		value string
		valid bool
	}{
		{"scenario.one", true}, {"proofkit.test.surface::scenario_one", true},
		{"surface::", false}, {"surface::anchor::extra", false},
		{"scenario.one\n", false}, {"not a scenario", false},
		{"scenario_20260924", false}, {"surface::anchor_20260924", false},
		{strings.Repeat("a", 257), false}, {"surface::" + strings.Repeat("a", 257), false},
	} {
		actual, err := AdmitSourceID(item.value, "scenario")
		if (err == nil) != item.valid || (item.valid && actual != item.value) {
			t.Fatalf("%q: result=%q error=%v, want valid=%t", item.value, actual, err, item.valid)
		}
	}
}
