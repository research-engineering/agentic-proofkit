package adoptionworkflow

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

// These operands and formulas are independent of the prerequisite declarations.
// They freeze the inherited acceptance policy, not the old repair prose.
func TestWorkflowAcceptanceTruthTableAndAdvertisedRepairs(t *testing.T) {
	cases := []struct {
		scenario string
		kinds    []string
		ready    func(bool, func(string) bool) bool
	}{
		{"new_repository", []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold", "bootstrap_witness_plan", "requirement_bindings", "witness_plan"}, func(preset bool, has func(string) bool) bool {
			return preset && has("gradual_adoption_bootstrap") && has("gradual_adoption_guidance") && has("repo_profile_scaffold") &&
				(has("bootstrap_witness_plan") || (has("requirement_bindings") && has("witness_plan")))
		}},
		{"existing_gradual_adoption", []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold", "requirement_bindings", "selective_gate_evidence", "selective_gate_plan", "witness_plan"}, func(preset bool, has func(string) bool) bool {
			return preset && has("gradual_adoption_bootstrap") && has("gradual_adoption_guidance") && has("repo_profile_scaffold") &&
				has("requirement_bindings") && has("selective_gate_evidence") && has("selective_gate_plan") && has("witness_plan")
		}},
		{"legacy_proof_migration", []string{"migration_plan", "requirement_bindings", "selective_gate_evidence", "selective_gate_plan"}, func(_ bool, has func(string) bool) bool {
			return has("migration_plan") && has("requirement_bindings") && has("selective_gate_evidence") && has("selective_gate_plan")
		}},
		{"release_channel", []string{"release_authority", "external_consumer", "registry_consumer"}, func(_ bool, has func(string) bool) bool {
			return has("release_authority") && (has("external_consumer") || has("registry_consumer"))
		}},
	}
	rows, repairBundles, incompleteAND := 0, 0, 0
	shape := blockersShape()
	schema := shape.JSONSchema()
	for _, item := range cases {
		t.Run(item.scenario, func(t *testing.T) {
			for mask := 0; mask < 1<<len(item.kinds); mask++ {
				provided := []string{}
				for index, kind := range item.kinds {
					if mask&(1<<index) != 0 {
						provided = append(provided, kind)
					}
				}
				for _, preset := range []bool{false, true} {
					rows++
					has := func(kind string) bool { return slices.Contains(provided, kind) }
					wantReady := item.ready(preset, has)
					input := prerequisiteTestInput(item.scenario, preset, provided)
					result, err := BuildResult(input)
					if err != nil {
						t.Fatal(err)
					}
					if (result.ExitCode == 0) != wantReady || (result.Plan["planState"] == planStateReady) != wantReady || (result.Record.State == "passed") != wantReady {
						t.Fatalf("mask=%b preset=%t: plan=%v exit=%d report=%s, want ready=%t", mask, preset, result.Plan["planState"], result.ExitCode, result.Record.State, wantReady)
					}
					blockers := result.Plan["blockers"].([]any)
					if err := shape.CheckGenerated(blockers, "blockers"); err != nil {
						t.Fatalf("mask=%b preset=%t: native projection: %v", mask, preset, err)
					}
					if err := schemacheck.Validate(schema, blockers); err != nil {
						t.Fatalf("mask=%b preset=%t: schema projection: %v", mask, preset, err)
					}
					if len(blockers) != 1 {
						continue
					}
					envelope, exit, err := BuildEnvelope(input)
					if err != nil || exit != 1 || len(envelope["clarificationQuestions"].([]any)) != 1 {
						t.Fatalf("sole blocker lost its question: exit=%d err=%v envelope=%v", exit, err, envelope)
					}
					question := envelope["clarificationQuestions"].([]any)[0].(map[string]any)
					alternatives := blockers[0].(map[string]any)["inputAlternatives"].([]any)
					if len(alternatives) == 0 {
						if preset || (item.scenario != "new_repository" && item.scenario != "existing_gradual_adoption") || question["expectedAnswerKind"] != presetChoiceAnswer || len(question["evidenceRefs"].([]any)) != 0 {
							t.Fatalf("not a scalar preset repair: %v", question)
						}
						continue
					}
					if question["expectedAnswerKind"] != missingContextAnswer {
						t.Fatalf("input repair lost its answer type: %v", question)
					}
					for _, raw := range alternatives {
						bundle := anyToStrings(raw.([]any))
						if len(bundle) == 0 || !slices.IsSorted(bundle) || len(slices.Compact(slices.Clone(bundle))) != len(bundle) {
							t.Fatalf("non-canonical repair bundle: %v", bundle)
						}
						for _, kind := range bundle {
							if has(kind) {
								t.Fatalf("repair repeats supplied kind %s", kind)
							}
						}
						for repairMask := 0; repairMask < 1<<len(bundle); repairMask++ {
							repaired := slices.Clone(provided)
							for index, kind := range bundle {
								if repairMask&(1<<index) != 0 {
									repaired = append(repaired, kind)
								}
							}
							got, err := BuildResult(prerequisiteTestInput(item.scenario, preset, repaired))
							complete := repairMask == (1<<len(bundle))-1
							if err != nil || (got.ExitCode == 0) != complete {
								t.Fatalf("have=%v bundle=%v repairMask=%b: exit=%d err=%v, complete=%t", provided, bundle, repairMask, got.ExitCode, err, complete)
							}
							if complete {
								repairBundles++
							} else if len(bundle) > 1 {
								incompleteAND++
							}
						}
					}
				}
			}
		})
	}
	if rows != 432 || repairBundles == 0 || incompleteAND == 0 {
		t.Fatalf("truth rows=%d successful bundles=%d incomplete AND=%d", rows, repairBundles, incompleteAND)
	}
	t.Logf("truth rows=%d successful bundles=%d incomplete AND=%d", rows, repairBundles, incompleteAND)
}

func TestWorkflowResidualRepairAlternatives(t *testing.T) {
	base := []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold"}
	for _, item := range []struct {
		provided []string
		want     inputAlternatives
		question string
	}{
		{nil, inputAlternatives{{"bootstrap_witness_plan"}, {"requirement_bindings", "witness_plan"}}, "(bootstrap_witness_plan) OR (requirement_bindings AND witness_plan)"},
		{[]string{"requirement_bindings"}, inputAlternatives{{"bootstrap_witness_plan"}, {"witness_plan"}}, "(bootstrap_witness_plan) OR (witness_plan)"},
		{[]string{"witness_plan"}, inputAlternatives{{"bootstrap_witness_plan"}, {"requirement_bindings"}}, "(bootstrap_witness_plan) OR (requirement_bindings)"},
	} {
		t.Run(fmt.Sprint(item.provided), func(t *testing.T) {
			input := prerequisiteTestInput("new_repository", true, append(slices.Clone(base), item.provided...))
			assertSoleRepair(t, input, item.want, item.question)
		})
	}
	assertSoleRepair(t, prerequisiteTestInput("release_channel", false, []string{"release_authority"}),
		inputAlternatives{{"external_consumer"}, {"registry_consumer"}}, "(external_consumer) OR (registry_consumer)")
}

func assertSoleRepair(t *testing.T, input map[string]any, want inputAlternatives, questionText string) {
	t.Helper()
	result, err := BuildResult(input)
	if err != nil || result.ExitCode != 1 || len(result.Plan["blockers"].([]any)) != 1 {
		t.Fatalf("expected one blocker: result=%v err=%v", result, err)
	}
	blocker := result.Plan["blockers"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(blocker["inputAlternatives"], want.json()) {
		t.Fatalf("repair alternatives=%v, want %v", blocker["inputAlternatives"], want)
	}
	if _, stale := blocker["requiredInputKinds"]; stale {
		t.Fatal("plan still advertises the ambiguous flat input list")
	}
	diagnostics := result.Record.RuleResults[0].Diagnostics
	if len(diagnostics) != 2 || diagnostics[1].Key != "inputAlternatives" || !reflect.DeepEqual(diagnostics[1].Value, want.json()) {
		t.Fatalf("report repair diverges from plan: %v", diagnostics)
	}
	envelope, _, err := BuildEnvelope(input)
	if err != nil {
		t.Fatal(err)
	}
	question := envelope["clarificationQuestions"].([]any)[0].(map[string]any)
	if question["question"] != "Provide caller-owned input refs for one complete bundle: "+questionText+"." {
		t.Fatalf("misleading repair question: %v", question)
	}
	for _, refs := range []any{question["evidenceRefs"], envelope["blockedPreconditions"].([]any)[0].(map[string]any)["evidenceRefs"]} {
		if !reflect.DeepEqual(refs, admit.StringSliceToAny(want.kinds())) {
			t.Fatalf("repair vocabulary diverges: %v", refs)
		}
	}
}

func TestWorkflowResidualBundlesAreMinimalAndDetached(t *testing.T) {
	alternatives := inputAlternatives{{"witness_plan", "requirement_bindings"}, {"requirement_bindings"}, {"bootstrap_witness_plan", "requirement_bindings"}, {"requirement_bindings"}}
	original := alternatives.json()
	got := alternatives.remaining(nil)
	if !reflect.DeepEqual(got, inputAlternatives{{"requirement_bindings"}}) {
		t.Fatalf("non-minimal bundles retained: %v", got)
	}
	got[0][0] = "changed"
	if !reflect.DeepEqual(alternatives.json(), original) {
		t.Fatal("projection mutated the prerequisite declaration")
	}
	if remaining := alternatives.remaining(map[string]inputRef{"requirement_bindings": {InputKind: "requirement_bindings"}}); len(remaining) != 0 {
		t.Fatalf("a completed alternative still blocks: %v", remaining)
	}
}

func TestWorkflowRepairStructuresRefuseAlgebraDrift(t *testing.T) {
	input := prerequisiteTestInput("new_repository", true, []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold"})
	plan, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	shape, schema := blockersShape(), OutputStructure()
	for name, alternatives := range map[string]any{
		"null":                   nil,
		"flat":                   []any{"bootstrap_witness_plan"},
		"scalar-only":            []any{},
		"empty-bundle":           []any{[]any{}},
		"unknown":                []any{[]any{"unknown_kind"}},
		"dropped-alternative":    []any{[]any{"requirement_bindings", "witness_plan"}},
		"AND-instead-of-OR":      []any{[]any{"bootstrap_witness_plan", "requirement_bindings", "witness_plan"}},
		"three-alternatives":     []any{[]any{"bootstrap_witness_plan"}, []any{"requirement_bindings"}, []any{"witness_plan"}},
		"duplicate-alternatives": []any{[]any{"bootstrap_witness_plan"}, []any{"bootstrap_witness_plan"}},
		"duplicate-kind":         []any{[]any{"bootstrap_witness_plan", "bootstrap_witness_plan"}},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := schemacheck.Normalize(plan)
			if err != nil {
				t.Fatal(err)
			}
			mutated := value.(map[string]any)
			blocker := mutated["blockers"].([]any)[0].(map[string]any)
			blocker["inputAlternatives"] = alternatives
			if shape.CheckGenerated(mutated["blockers"], "blockers") == nil || schemacheck.Validate(schema, mutated) == nil {
				t.Fatalf("native/schema accepted %s drift", name)
			}
		})
	}
	presetPlan, _, err := Build(prerequisiteTestInput("new_repository", false, []string{
		"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold", "bootstrap_witness_plan",
	}))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"legacy-flat-field": func(blocker map[string]any) {
			delete(blocker, "inputAlternatives")
			blocker["requiredInputKinds"] = []any{}
		},
		"preset-input-repair": func(blocker map[string]any) {
			blocker["inputAlternatives"] = []any{[]any{"repo_profile_scaffold"}}
		},
	} {
		value, err := schemacheck.Normalize(presetPlan)
		if err != nil {
			t.Fatal(err)
		}
		mutated := value.(map[string]any)
		mutate(mutated["blockers"].([]any)[0].(map[string]any))
		if shape.CheckGenerated(mutated["blockers"], "blockers") == nil || schemacheck.Validate(schema, mutated) == nil {
			t.Fatalf("native/schema accepted %s drift", name)
		}
	}
}

func prerequisiteTestInput(scenario string, preset bool, kinds []string) map[string]any {
	input := validWorkflowInput()
	input["scenario"], input["presetId"] = scenario, nil
	if preset {
		input["presetId"] = "python_service"
	}
	refs := []any{}
	for _, kind := range kinds {
		refs = append(refs, map[string]any{"inputKind": kind, "path": "inputs/" + kind + ".json", "refId": "example." + kind})
	}
	input["inputRefs"] = refs
	return input
}
