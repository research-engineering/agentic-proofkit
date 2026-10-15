package requirementsourcetransition

import (
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// A reviewer needs the requirements behind each transition count, not only
// the count; each list is sorted and its length equals the summary count.
func TestTransitionNamesAffectedRequirementsBehindEachCount(t *testing.T) {
	previous := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
	appendRequirement(previous, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-004", state: "active"})
	appendRequirement(previous, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-002", state: "active"})
	next := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
	appendRequirement(next, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-004", state: "active"})
	appendRequirement(next, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-003", state: "active"})
	replaceRequirement(next, requirementFixture{
		id: "REQ-PROOFKIT-TRANSITION-001", state: "superseded",
		evidence:     []any{"docs/evidence/previous.md", "docs/evidence/superseded.md"},
		replacements: []any{"REQ-PROOFKIT-TRANSITION-003"},
	})
	appendRequirement(next, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-005", state: "active"})

	record, _, err := Build(transitionInput(previous, next))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"addedRequirementIds":            {"REQ-PROOFKIT-TRANSITION-003", "REQ-PROOFKIT-TRANSITION-005"},
		"lifecycleChangedRequirementIds": {"REQ-PROOFKIT-TRANSITION-001"},
		"missingRequirementIds":          {"REQ-PROOFKIT-TRANSITION-002"},
	}
	counts := map[string]string{
		"addedRequirementIds":            "addedRequirementCount",
		"lifecycleChangedRequirementIds": "lifecycleChangedRequirementCount",
		"missingRequirementIds":          "missingRequirementCount",
	}
	if len(record.Diagnostics) != 5 {
		t.Fatalf("diagnostics = %v, want failures, sourcePaths and three identity lists", record.Diagnostics)
	}
	for _, diagnostic := range record.Diagnostics[2:] {
		ids, ok := want[diagnostic.Key]
		if !ok || !reflect.DeepEqual(diagnostic.Value, admit.StringSliceToAny(ids)) {
			t.Fatalf("%s = %v, want %v", diagnostic.Key, diagnostic.Value, ids)
		}
		if record.Summary[counts[diagnostic.Key]] != len(ids) {
			t.Fatalf("%s = %v, want the identity list length %d", counts[diagnostic.Key], record.Summary[counts[diagnostic.Key]], len(ids))
		}
	}
	if err := transitionOutputShape.CheckGenerated(record.JSONValue(), "transition output"); err != nil {
		t.Fatal(err)
	}
}
