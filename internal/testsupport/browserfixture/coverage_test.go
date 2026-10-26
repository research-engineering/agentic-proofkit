package browserfixture

import (
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
)

// The static coverage gap fixture keeps the covered requirement of the
// structured coverage input and adds one active requirement that no proof
// binding route or test evidence covers; the coverage view must report it as
// a gap and the view as failed.
func TestCoverageGapInputRendersAnUncoveredRequirementAsAFailure(t *testing.T) {
	input, err := CoverageGapInput()
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := requirementcoverageview.BuildJSON(input, requirementcoverageview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := requirementcoverageview.AdmitOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if view["state"] != "failed" || view["failureCount"] != json.Number("1") {
		t.Fatalf("coverage gap view state = %v with %v failures, want failed with one", view["state"], view["failureCount"])
	}
	states := map[string]string{}
	for _, raw := range view["requirementCoverage"].([]any) {
		requirement := raw.(map[string]any)
		states[requirement["requirementId"].(string)] = requirement["coverageState"].(string)
		if requirement["requirementId"] == "REQ-BROWSER-COVERAGE-002" && len(requirement["testIds"].([]any)) != 0 {
			t.Fatalf("the uncovered requirement must have no test evidence: %v", requirement["testIds"])
		}
	}
	if len(states) != 2 || states["REQ-BROWSER-COVERAGE-001"] != "mapped_to_declared_semantic_falsifier_route" || states["REQ-BROWSER-COVERAGE-002"] != "missing_proof_binding_route" {
		t.Fatalf("coverage gap states = %v", states)
	}
	covered, err := CoverageInput("structured")
	if err != nil {
		t.Fatal(err)
	}
	coveredRaw, _, err := requirementcoverageview.BuildJSON(covered, requirementcoverageview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	coveredView, err := requirementcoverageview.AdmitOutput(coveredRaw)
	if err != nil {
		t.Fatal(err)
	}
	if coveredView["state"] == "failed" {
		t.Fatal("the structured coverage input without the gap must not fail; the gap alone makes the view fail")
	}
}
