package testevidenceinventory

import "strings"

const unclassifiedInventoryGap = "unclassified_test_inventory_gap"

var diagnosticClasses = map[string]string{
	"candidate_only":                      "candidate_only",
	"declared_duplicate_falsifier":        "declared_duplicate_falsifier",
	"invalid_falsifier_supersession":      "invalid_falsifier_supersession",
	"missing_declared_route_anchor":       "missing_declared_route_anchor",
	"missing_executable_command_ref":      "missing_executable_command_ref",
	"proof_route_candidate":               "proof_route_candidate",
	"route_only_nonclaim":                 "routing_smoke_only",
	"selector_fragility":                  "selector_fragility",
	"incomplete_declared_oracle_metadata": "incomplete_declared_oracle_metadata",
	"wrong_evidence_boundary":             "wrong_evidence_boundary",
}

func diagnosticClassID(diagnostic string) string {
	prefix, rest, present := strings.Cut(diagnostic, ":")
	if present {
		if prefix == "quality_finding" {
			class, _, _ := strings.Cut(rest, ":")
			return class
		}
		if class, ok := diagnosticClasses[prefix]; ok {
			return class
		}
	}
	return unclassifiedInventoryGap
}

// ClassificationIDs includes every class emitted from admitted inventory or
// discovery facts, including the fallback for unrecognized diagnostic prefixes.
func ClassificationIDs() []string {
	ids := []string{unclassifiedInventoryGap}
	for _, class := range diagnosticClasses {
		ids = append(ids, class)
	}
	for class := range qualityFindingClassSet {
		ids = append(ids, class)
	}
	return sortedUnique(ids)
}
