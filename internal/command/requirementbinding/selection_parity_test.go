package requirementbinding

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func selectionParityInput() Input {
	return Input{
		BindingID: "binding.selection",
		Requirements: []Requirement{
			{RequirementID: "REQ-A", OwnerID: "owner.a", SpecPath: "spec/a.json", ClaimLevel: "blocking", ProofState: "witness_backed", NonClaims: []string{}},
			{RequirementID: "REQ-B", OwnerID: "owner.b", SpecPath: "spec/b.json", ClaimLevel: "blocking", ProofState: "witness_backed", NonClaims: []string{}},
			{RequirementID: "REQ-C", OwnerID: "owner.c", SpecPath: "spec/shared.json", ClaimLevel: "blocking", ProofState: "witness_backed", NonClaims: []string{}},
			{RequirementID: "REQ-D", OwnerID: "owner.d", SpecPath: "spec/shared.json", ClaimLevel: "blocking", ProofState: "witness_backed", NonClaims: []string{}},
			{RequirementID: "REQ-E", OwnerID: "owner.e", SpecPath: "spec/e.json", ClaimLevel: "blocking", ProofState: "witness_backed", NonClaims: []string{}},
		},
		Bindings: []Binding{
			{RequirementID: "REQ-A", ScenarioID: "scenario.a", WitnessID: "witness.a", WitnessKind: "contract", WitnessPath: "test/shared.go", CommandIDs: []string{"command.a"}, EnvironmentClasses: []string{"local-go"}},
			{RequirementID: "REQ-B", ScenarioID: "scenario.b", WitnessID: "witness.b", WitnessKind: "contract", WitnessPath: "test/b.go", CommandIDs: []string{"command.a"}, EnvironmentClasses: []string{"local-go"}},
			{RequirementID: "REQ-C", ScenarioID: "scenario.c", WitnessID: "witness.c", WitnessKind: "contract", WitnessPath: "test/c.go", CommandIDs: []string{"command.a"}, EnvironmentClasses: []string{"local-go"}},
			{RequirementID: "REQ-D", ScenarioID: "scenario.d", WitnessID: "witness.d", WitnessKind: "contract", WitnessPath: "test/d.go", CommandIDs: []string{"command.a"}, EnvironmentClasses: []string{"local-go"}},
			{RequirementID: "REQ-E", ScenarioID: "scenario.e", WitnessID: "witness.e", WitnessKind: "contract", WitnessPath: "test/shared.go", CommandIDs: []string{"command.a"}, EnvironmentClasses: []string{"local-go"}},
			{RequirementID: "REQ-E", ScenarioID: "scenario.e.extra", WitnessID: "witness.e.extra", WitnessKind: "contract", WitnessPath: "test/extra.go", CommandIDs: []string{"command.a"}, EnvironmentClasses: []string{"local-go"}},
		},
		WitnessCommands: []WitnessCommand{{CommandID: "command.a", Command: "go test ./test", EnvironmentClasses: []string{"local-go"}}},
		NonClaims:       []string{"Selection fixtures do not execute witnesses."},
	}
}

// This is the pre-index selection algorithm, deliberately kept test-local.
func baselineSelectedRequirement(requirement Requirement, bindings []Binding, selection Selection) bool {
	if len(selection.ChangedPaths) == 0 && len(selection.OwnerIDs) == 0 && len(selection.RequirementIDs) == 0 {
		return true
	}
	for _, id := range selection.RequirementIDs {
		if id == requirement.RequirementID {
			return true
		}
	}
	for _, id := range selection.OwnerIDs {
		if id == requirement.OwnerID {
			return true
		}
	}
	for _, path := range selection.ChangedPaths {
		if path == requirement.SpecPath {
			return true
		}
		for _, binding := range bindings {
			if binding.RequirementID == requirement.RequirementID && path == binding.WitnessPath {
				return true
			}
		}
	}
	return false
}

func TestSelectionExplicitORAndBaseline(t *testing.T) {
	expectedByMask := [][]string{
		{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"},
		{"REQ-A"},
		{"REQ-B"},
		{"REQ-A", "REQ-B"},
		{"REQ-C", "REQ-D"},
		{"REQ-A", "REQ-C", "REQ-D"},
		{"REQ-B", "REQ-C", "REQ-D"},
		{"REQ-A", "REQ-B", "REQ-C", "REQ-D"},
		{"REQ-A", "REQ-E"},
		{"REQ-A", "REQ-E"},
		{"REQ-A", "REQ-B", "REQ-E"},
		{"REQ-A", "REQ-B", "REQ-E"},
		{"REQ-A", "REQ-C", "REQ-D", "REQ-E"},
		{"REQ-A", "REQ-C", "REQ-D", "REQ-E"},
		{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"},
		{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"},
	}
	for mask := 0; mask < 16; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			input := selectionParityInput()
			if mask&1 != 0 {
				input.Selection.RequirementIDs = []string{"REQ-A"}
			}
			if mask&2 != 0 {
				input.Selection.OwnerIDs = []string{"owner.b"}
			}
			if mask&4 != 0 {
				input.Selection.ChangedPaths = append(input.Selection.ChangedPaths, "spec/shared.json")
			}
			if mask&8 != 0 {
				input.Selection.ChangedPaths = append(input.Selection.ChangedPaths, "test/shared.go")
			}
			want := expectedByMask[mask]
			result, err := Build(InputValue(input))
			if err != nil || result.Record.State != "passed" {
				t.Fatalf("Build: %v, %s", err, result.Record.State)
			}
			got := []string{}
			for _, item := range result.Slice["selectedRequirements"].([]any) {
				got = append(got, item.(map[string]any)["requirementId"].(string))
			}
			baseline := []string{}
			for _, requirement := range result.Input.Requirements {
				if baselineSelectedRequirement(requirement, result.Input.Bindings, result.Input.Selection) {
					baseline = append(baseline, requirement.RequirementID)
				}
			}
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(got, baseline) {
				t.Fatalf("selected=%v expected=%v baseline=%v", got, want, baseline)
			}
		})
	}
}

func TestSelectionFullOutputParity(t *testing.T) {
	// SHA-256 of the complete JSON Result at base 27fcb8e, not selected fields.
	wants := map[string]string{
		"all":            "25be2d63ef645c91e2ba981544bd7cee827d5323b0b8b9b3a49129eb2dc35fad",
		"sparse":         "3175d5f60e79c2ec8de5e5b26ac7330bd922c0b549d51aab1b858eef2b40c03d",
		"dense":          "ef66ca532e17aa87a9ce995e326b6b8a06c7750d741e628f3427f18ad96d8609",
		"no-match":       "c492d11fdf836097849646e5fad438ebd9592f4981a1b22bdf8f4f7427eb65d1",
		"mixed-negative": "b7b31b73f87d56e26c54c6ef589560e9e6db8985310751f3590c5bf84a354017",
	}
	for _, name := range []string{"all", "sparse", "dense", "no-match", "mixed-negative"} {
		t.Run(name, func(t *testing.T) {
			input := selectionParityInput()
			switch name {
			case "sparse":
				input.Selection.ChangedPaths = []string{"test/extra.go"}
			case "dense":
				input.Selection = Selection{RequirementIDs: []string{"REQ-A"}, OwnerIDs: []string{"owner.b"}, ChangedPaths: []string{"spec/shared.json", "test/shared.go"}}
			case "no-match":
				input.Selection = Selection{RequirementIDs: []string{"REQ-UNKNOWN"}, OwnerIDs: []string{"owner.unknown"}, ChangedPaths: []string{"spec", "test/shared.go.extra"}}
			case "mixed-negative":
				input.Selection.ChangedPaths = []string{"test/shared.go"}
				input.Bindings[0].RequirementID = "REQ-UNKNOWN"
				input.Bindings[1].CommandIDs = []string{"command.unknown"}
			}
			raw := InputValue(input)
			before, _ := json.Marshal(raw)
			result, err := Build(raw)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(raw)
			if string(before) != string(after) {
				t.Fatal("Build mutated caller input")
			}
			wantState := "passed"
			if name == "mixed-negative" || name == "no-match" {
				wantState = "failed"
			}
			if result.Record.State != wantState {
				t.Fatalf("state=%s want %s", result.Record.State, wantState)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%x", sha256.Sum256(encoded))
			if got != wants[name] {
				t.Fatalf("full output digest = %s", got)
			}
		})
	}
}

func TestSelectionLazyRoutesPreservePublicProjection(t *testing.T) {
	for _, test := range []struct {
		name      string
		selection Selection
		wantIDs   []string
		wantState string
	}{
		{"all", Selection{}, []string{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"}, "passed"},
		{"direct-with-changed-paths", Selection{RequirementIDs: []string{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"}, ChangedPaths: []string{"missing.go"}}, []string{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"}, "passed"},
		{"owners-with-changed-paths", Selection{OwnerIDs: []string{"owner.a", "owner.b", "owner.c", "owner.d", "owner.e"}, ChangedPaths: []string{"missing.go"}}, []string{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"}, "passed"},
		{"spec-only", Selection{ChangedPaths: []string{"missing.go", "spec/a.json", "spec/b.json", "spec/shared.json", "spec/e.json"}}, []string{"REQ-A", "REQ-B", "REQ-C", "REQ-D", "REQ-E"}, "passed"},
		{"direct-then-witness", Selection{RequirementIDs: []string{"REQ-A"}, ChangedPaths: []string{"test/b.go", "test/extra.go"}}, []string{"REQ-A", "REQ-B", "REQ-E"}, "passed"},
		{"unknown-control", Selection{RequirementIDs: []string{"REQ-UNKNOWN"}, ChangedPaths: []string{"missing.go"}}, []string{}, "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := selectionParityInput()
			input.Selection = test.selection
			raw := InputValue(input)
			before, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Build(raw)
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(raw)
			if err != nil || string(before) != string(after) {
				t.Fatalf("caller input changed: %v", err)
			}
			wantProjection := []any{}
			wantIDs := []string{}
			for i, requirement := range result.Input.Requirements {
				if baselineSelectedRequirement(requirement, result.Input.Bindings, result.Input.Selection) {
					wantIDs = append(wantIDs, requirement.RequirementID)
					wantProjection = append(wantProjection, result.Graph["requirements"].([]any)[i])
				}
			}
			if result.Record.State != test.wantState || !reflect.DeepEqual(wantIDs, test.wantIDs) || !reflect.DeepEqual(result.Slice["selectedRequirements"], wantProjection) {
				t.Fatalf("state=%s want=%s; ids=%v want=%v; projection=%v", result.Record.State, test.wantState, wantIDs, test.wantIDs, result.Slice["selectedRequirements"])
			}
			if result.Slice["selectedRequirementCount"] != len(test.wantIDs) || result.Slice["omittedRequirementCount"] != len(input.Requirements)-len(test.wantIDs) {
				t.Fatal("selection counts changed")
			}
			wantCommands := []any{}
			if len(test.wantIDs) > 0 {
				wantCommands = append(wantCommands, "command.a")
			}
			if !reflect.DeepEqual(result.Slice["selectedCommandIds"], wantCommands) {
				t.Fatalf("selected commands=%v want=%v", result.Slice["selectedCommandIds"], wantCommands)
			}
		})
	}
}
