package testevidenceinventory

import (
	"reflect"
	"testing"
)

func TestDiagnosticClassificationPreservesPrefixAndFallbackSemantics(t *testing.T) {
	for _, test := range []struct{ diagnostic, want string }{
		{"candidate_only:test.x", "candidate_only"},
		{"declared_duplicate_falsifier:test.x", "declared_duplicate_falsifier"},
		{"invalid_falsifier_supersession:test.x", "invalid_falsifier_supersession"},
		{"missing_declared_route_anchor:test.x", "missing_declared_route_anchor"},
		{"missing_executable_command_ref:test.x", "missing_executable_command_ref"},
		{"proof_route_candidate:test.x", "proof_route_candidate"},
		{"route_only_nonclaim:test.x", "routing_smoke_only"},
		{"selector_fragility:test.x", "selector_fragility"},
		{"incomplete_declared_oracle_metadata:test.x", "incomplete_declared_oracle_metadata"},
		{"wrong_evidence_boundary:test.x", "wrong_evidence_boundary"},
		{"quality_finding:empty_oracle:test.x:detail", "empty_oracle"},
		{"quality_finding:wrong_boundary", "wrong_boundary"},
		{"quality_finding:", ""},
		{"missing_declared_assertion_signal:test.x", "unclassified_test_inventory_gap"},
		{"candidate_only", "unclassified_test_inventory_gap"},
		{"candidate_only_suffix:test.x", "unclassified_test_inventory_gap"},
		{"", "unclassified_test_inventory_gap"},
	} {
		if got := diagnosticClassID(test.diagnostic); got != test.want {
			t.Fatalf("classification(%q)=%q want %q", test.diagnostic, got, test.want)
		}
	}
	want := []string{"candidate_only", "declared_duplicate_falsifier", "duplicate_falsifier_candidate", "empty_oracle", "fixture_leak_risk",
		"flaky_time", "implementation_mirror", "import_cost_leak", "incomplete_declared_oracle_metadata", "invalid_falsifier_supersession",
		"missing_declared_route_anchor", "missing_edge", "missing_executable_command_ref", "mock_tests_mock", "over_broad_integration",
		"proof_route_candidate", "routing_smoke_only", "selector_fragility", "snapshot_without_oracle", "tautology",
		"unasserted_diagnostic", "unclassified_test_inventory_gap", "wrong_boundary", "wrong_evidence_boundary"}
	actual := ClassificationIDs()
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("classification vocabulary=%v want %v", actual, want)
	}
	actual[0] = "changed"
	if !reflect.DeepEqual(ClassificationIDs(), want) {
		t.Fatal("classification vocabulary aliases caller mutation")
	}
}
