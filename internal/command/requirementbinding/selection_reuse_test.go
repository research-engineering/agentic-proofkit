package requirementbinding

import (
	"fmt"
	"reflect"
	"testing"
)

func TestBuildSliceReusesSelectionIndexAcrossRequirements(t *testing.T) {
	for _, test := range []struct {
		name        string
		selection   Selection
		selectedIDs []string
		state       string
	}{
		{"empty-requirement-map", Selection{ChangedPaths: []string{"missing.go"}}, []string{}, "passed"},
		{"unknown-id", Selection{RequirementIDs: []string{"REQ-UNKNOWN"}}, []string{}, "failed"},
		{"direct-then-witness", Selection{RequirementIDs: []string{"REQ-A"}, ChangedPaths: []string{"test/b.go"}}, []string{"REQ-A", "REQ-B"}, "passed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			allocations := make([]float64, 0, 2)
			for _, size := range []int{5, 64} {
				input := selectionParityInput()
				input.Selection = test.selection
				for len(input.Requirements) < size {
					n := len(input.Requirements)
					id := fmt.Sprintf("REQ-EXTRA-%04d", n)
					input.Requirements = append(input.Requirements, Requirement{
						RequirementID: id, OwnerID: "owner.extra", SpecPath: "spec/extra.json",
						ClaimLevel: "blocking", ProofState: "witness_backed", NonClaims: []string{},
					})
					input.Bindings = append(input.Bindings, Binding{
						RequirementID: id, ScenarioID: fmt.Sprintf("scenario.extra.%d", n),
						WitnessID: fmt.Sprintf("witness.extra.%d", n), WitnessKind: "contract",
						WitnessPath: "test/extra-unselected.go", CommandIDs: []string{"command.a"},
						EnvironmentClasses: []string{"local-go"},
					})
				}
				result, err := Build(InputValue(input))
				if err != nil || result.Record.State != test.state {
					t.Fatalf("fixture size %d: error=%v state=%s", size, err, result.Record.State)
				}
				// Hold admission, graph construction and selected output size constant.
				// Extra unmatched requirements must not allocate new selection maps.
				var slice map[string]any
				allocations = append(allocations, testing.AllocsPerRun(25, func() {
					slice = buildSlice(result.Input, result.Graph)
				}))
				ids := []string{}
				for _, value := range slice["selectedRequirements"].([]any) {
					ids = append(ids, value.(map[string]any)["requirementId"].(string))
				}
				if !reflect.DeepEqual(ids, test.selectedIDs) || !reflect.DeepEqual(slice, result.Slice) {
					t.Fatalf("fixture size %d: production selection changed", size)
				}
			}
			if allocations[1] != allocations[0] {
				t.Fatalf("unmatched requirement growth changed selection allocations: %v", allocations)
			}
		})
	}
}
