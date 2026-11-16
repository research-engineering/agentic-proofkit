package adoptionworkflow

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestWorkflowPreparedInputsRefuseStdin(t *testing.T) {
	for kind := range inputKinds {
		for _, path := range []string{"-", "inputs/-.json", "input-with-hyphens.json"} {
			t.Run(kind+"/"+path, func(t *testing.T) {
				input := validWorkflowInput()
				input["inputRefs"] = []any{map[string]any{"inputKind": kind, "path": path, "refId": "example.input"}}
				wrapped := map[string]any{"schema": "proofkit.adoption-workflow.v1", "workflow": input}
				for name, carrier := range map[string]struct {
					input  any
					schema map[string]any
					build  func(any) (map[string]any, int, error)
				}{
					"direct":  {input, InputStructure(), Build},
					"wrapped": {wrapped, ContractInputStructure(), BuildFromContractEnvelope},
				} {
					_, _, err := carrier.build(carrier.input)
					wantRefused := path == "-"
					if (err != nil) != wantRefused {
						t.Fatalf("%s: err=%v, wantRefused=%t", name, err, wantRefused)
					}
					if schemaErr := schemacheck.Validate(carrier.schema, carrier.input); (schemaErr != nil) != wantRefused {
						t.Fatalf("%s schema: %v, wantRefused=%t", name, schemaErr, wantRefused)
					}
				}
			})
		}
	}
}

func TestWorkflowActionInputsResolveToCommandOperands(t *testing.T) {
	for _, scenario := range slices.Sorted(maps.Keys(scenarios)) {
		for _, collision := range []bool{false, true} {
			input := completeLinkageInput(scenario)
			if collision {
				refs := input["inputRefs"].([]any)
				refs[0].(map[string]any)["refId"] = "p"
				refs[1].(map[string]any)["refId"] = "proofkit.adoption-workflow.context.p"
			}
			result, err := BuildResult(input)
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("%s control: exit=%d err=%v", scenario, result.ExitCode, err)
			}
			envelope, code, err := BuildEnvelope(input)
			if err != nil || code != 0 {
				t.Fatalf("%s envelope: exit=%d err=%v", scenario, code, err)
			}
			contexts := map[string]string{}
			for _, raw := range envelope["contextRefs"].([]any) {
				ref := raw.(map[string]any)
				contexts[ref["refId"].(string)] = ref["ref"].(string)
			}
			commandPaths := map[string][]string{}
			for _, raw := range envelope["commands"].([]any) {
				command := raw.(map[string]any)
				argv := anyToStrings(command["argv"].([]any))
				for i, value := range argv {
					if value == "--input" {
						commandPaths[command["commandId"].(string)] = []string{argv[i+1]}
					}
				}
			}
			matched := 0
			for _, raw := range envelope["actionPlan"].([]any) {
				action := raw.(map[string]any)
				want := []string{}
				for _, id := range anyToStrings(action["commandIds"].([]any)) {
					want = append(want, commandPaths[id]...)
				}
				got := []string{}
				for _, id := range anyToStrings(action["evidenceRefs"].([]any)) {
					path, ok := contexts[id]
					if !ok {
						t.Fatalf("%s action has unresolved input %q", scenario, id)
					}
					got = append(got, path)
				}
				slices.Sort(want)
				slices.Sort(got)
				want = slices.Compact(want)
				if !slices.Equal(got, want) {
					t.Fatalf("%s action %v: resolved paths=%v, command inputs=%v", scenario, action["stepId"], got, want)
				}
				matched += len(got)
			}
			if matched == 0 {
				t.Fatalf("%s did not exercise an input-bearing action", scenario)
			}
			for _, raw := range envelope["routeQuestions"].([]any) {
				question := raw.(map[string]any)
				if question["question"] != "what changed" {
					continue
				}
				got := []string{}
				for _, id := range anyToStrings(question["evidenceRefs"].([]any)) {
					path, ok := contexts[id]
					if !ok {
						t.Fatalf("what changed contains an unresolved context %q", id)
					}
					got = append(got, path)
				}
				want := []string{}
				for _, raw := range input["inputRefs"].([]any) {
					want = append(want, raw.(map[string]any)["path"].(string))
				}
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Fatalf("what changed paths=%v, supplied=%v", got, want)
				}
			}
		}
	}
}

func TestWorkflowClarificationRequestsTheMissingOperand(t *testing.T) {
	for _, scenario := range []string{"new_repository", "existing_gradual_adoption"} {
		for _, absent := range []bool{false, true} {
			input := completeLinkageInput(scenario)
			input["presetId"] = nil
			if absent {
				delete(input, "presetId")
			}
			envelope, exit, err := BuildEnvelope(input)
			if err != nil || exit != 1 {
				t.Fatalf("missing preset: exit=%d err=%v", exit, err)
			}
			questions := envelope["clarificationQuestions"].([]any)
			if len(questions) != 1 {
				t.Fatalf("missing only preset: questions=%v", questions)
			}
			question := questions[0].(map[string]any)
			if question["expectedAnswerKind"] != "preset_choice" || !strings.Contains(question["question"].(string), "presetId") {
				t.Fatalf("wrong repair operand: %v", question)
			}
			if !strings.Contains(envelope["bounds"].(map[string]any)["escalation"].(string), "presetId") {
				t.Fatal("missing-preset escalation must identify the scalar repair")
			}
			for _, preset := range stackpreset.IDs() {
				if !strings.Contains(question["question"].(string), preset) {
					t.Fatalf("question omits supported preset %s", preset)
				}
				input["presetId"] = preset
				if result, err := BuildResult(input); err != nil || result.ExitCode != 0 {
					t.Fatalf("preset alone failed to resolve blocker: exit=%d err=%v", result.ExitCode, err)
				}
			}
			input["inputRefs"] = []any{}
			missingRefs, exit, err := BuildEnvelope(input)
			if err != nil || exit != 1 {
				t.Fatalf("missing refs: exit=%d err=%v", exit, err)
			}
			for _, raw := range missingRefs["clarificationQuestions"].([]any) {
				question := raw.(map[string]any)
				if question["expectedAnswerKind"] != "missing_context_ref" || len(question["evidenceRefs"].([]any)) == 0 {
					t.Fatalf("missing ref was not a ref question: %v", question)
				}
			}
		}
	}
}

func completeLinkageInput(scenario string) map[string]any {
	input := validWorkflowInput()
	input["scenario"], input["presetId"] = scenario, "python_service"
	refs := []any{}
	for _, kind := range slices.Sorted(maps.Keys(inputKinds)) {
		refs = append(refs, map[string]any{"inputKind": kind, "path": "inputs/" + kind + ".json", "refId": "example." + kind})
	}
	input["inputRefs"] = refs
	return input
}
