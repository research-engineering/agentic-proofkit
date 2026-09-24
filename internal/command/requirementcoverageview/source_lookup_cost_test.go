package requirementcoverageview

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

func TestUnknownProofRequirementLookupHasLinearAllocationGrowth(t *testing.T) {
	fixture := func(count int) compositeInput {
		source := validCoverageInput(t).(map[string]any)["requirementSource"].(map[string]any)
		group := coverageSourceGroup(source)
		seed := group["members"].([]any)[0]
		members := make([]any, count)
		proof := proofProjection{Requirements: map[string]proofRequirement{}}
		for i := range count {
			member := cloneCoverageJSONValue(seed).(map[string]any)
			id := fmt.Sprintf("REQ-LOOKUP-%04d", i)
			member["requirementId"] = id
			members[i] = member
			proof.Requirements[id] = proofRequirement{}
		}
		group["members"] = members
		admitted, err := requirementsourceadmission.Evaluate(source)
		if err != nil || admitted.ExitCode != 0 {
			t.Fatalf("source premise: %v %v", err, admitted.Failures)
		}
		return compositeInput{Source: admitted.Source, Proof: proof, CoverageUniverse: coverageUniverse{OwnerIDs: []string{"owner.outside"}}}
	}
	measure := func(input compositeInput) float64 {
		return testing.AllocsPerRun(3, func() {
			failures, warnings := []string{}, []string{}
			rows := buildRequirementCoverage(input, nil, nil, &failures, &warnings)
			if len(rows) != 0 || len(failures) != 0 || len(warnings) != 0 {
				t.Fatal("known out-of-scope requirements changed output")
			}
		})
	}
	small, large := fixture(100), fixture(400)
	a, b := measure(small), measure(large)
	t.Logf("known-source lookup allocations: 100 members=%.0f, 400 members=%.0f", a, b)
	if a <= 0 || b > 6*a {
		t.Fatalf("fourfold input grows allocations from %.0f to %.0f; repeated whole-source lookup returned", a, b)
	}
	large.Proof.Requirements["REQ-UNKNOWN"] = proofRequirement{}
	failures, warnings := []string{}, []string{}
	if rows := buildRequirementCoverage(large, nil, nil, &failures, &warnings); len(rows) != 0 || !reflect.DeepEqual(failures, []string{"proof_binding_unknown_requirement:REQ-UNKNOWN"}) || len(warnings) != 0 {
		t.Fatalf("unknown/known out-of-scope distinction changed: %v %v", failures, warnings)
	}
}
