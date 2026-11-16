package adoptionworkflow

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
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
			changedQuestions := 0
			for _, raw := range envelope["routeQuestions"].([]any) {
				question := raw.(map[string]any)
				if question["questionId"] != "proofkit.adoption-workflow.question.what-changed" {
					continue
				}
				changedQuestions++
				if question["question"] != "what changed" {
					t.Fatal("what-changed question lost its declared role")
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
			if changedQuestions != 1 {
				t.Fatalf("what-changed question count=%d, want 1", changedQuestions)
			}
		}
	}
}

func TestWorkflowBlockedActionDoesNotInventContextRefs(t *testing.T) {
	for scenario := range scenarios {
		input := validWorkflowInput()
		input["scenario"], input["inputRefs"] = scenario, []any{}
		envelope, code, err := BuildEnvelope(input)
		if err != nil || code != 1 {
			t.Fatalf("%s blocked envelope: exit=%d err=%v", scenario, code, err)
		}
		actions := envelope["actionPlan"].([]any)
		if len(actions) != 1 || len(envelope["commands"].([]any)) != 0 {
			t.Fatalf("%s did not reach the command-free repair action", scenario)
		}
		action := actions[0].(map[string]any)
		if len(action["evidenceRefs"].([]any)) != 0 {
			t.Fatalf("repair action invented local refs: %v", action["evidenceRefs"])
		}
		if len(envelope["blockedPreconditions"].([]any)) == 0 || len(envelope["clarificationQuestions"].([]any)) == 0 {
			t.Fatal("missing-input obligations disappeared from the repair packet")
		}
	}
}

func TestWorkflowContextPathPreservesCommandOperand(t *testing.T) {
	for _, size := range []int{511, 512, 513, 600} {
		input := validWorkflowInput()
		path := strings.Repeat("d/", (size-1)/2) + strings.Repeat("x", 1+(size-1)%2)
		input["inputRefs"].([]any)[0].(map[string]any)["path"] = path
		envelope, code, err := BuildEnvelope(input)
		if err != nil || code != 0 {
			t.Fatalf("%d-byte path: exit=%d err=%v", size, code, err)
		}
		matched := 0
		for _, raw := range envelope["contextRefs"].([]any) {
			ref := raw.(map[string]any)
			if ref["refId"] == "proofkit.adoption-workflow.context.proofkit.release-authority" {
				matched++
				if ref["ref"] != path {
					t.Fatalf("%d-byte structural path changed", size)
				}
			}
		}
		if matched != 1 {
			t.Fatalf("context match count=%d, want 1", matched)
		}
		for _, raw := range envelope["commands"].([]any) {
			command := raw.(map[string]any)
			if command["commandId"] == "proofkit.adoption-workflow.command.release-authority" && command["argv"].([]any)[3] != path {
				t.Fatal("command path differs from the caller operand")
			}
		}
	}
}

func TestWorkflowPathRolesPreserveExactRenderedArgv(t *testing.T) {
	python, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, "/opt/task-validation/bin/python")
	if err != nil {
		t.Fatal(err)
	}
	npm, err := cliexec.AdmitLauncherProfile(cliexec.ProfileNPMOffline, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, renderer := range []cliexec.Renderer{cliexec.PathRenderer(), npm, python} {
		input := validWorkflowInput()
		input["inputRefs"].([]any)[0].(map[string]any)["path"] = "inputs/task-requirements.json"
		input["inputRefs"].([]any)[1].(map[string]any)["path"] = "inputs/task-validation.json"
		plan, code, err := BuildWithRenderer(input, renderer)
		if err != nil || code != 0 {
			t.Fatalf("control: exit=%d err=%v", code, err)
		}
		envelope, code, err := BuildEnvelopeWithRenderer(input, renderer)
		if err != nil || code != 0 || len(envelope["omitted"].([]any)) != 0 {
			t.Fatalf("envelope: exit=%d err=%v", code, err)
		}
		commands := envelope["commands"].([]any)
		if len(commands) != 2 {
			t.Fatal("ready route lost a declared command")
		}
		for _, raw := range commands {
			command := raw.(map[string]any)
			original := workflowCommand(t, plan, command["commandId"].(string))
			if !slices.Equal(anyToStrings(command["argv"].([]any)), anyToStrings(original["argv"].([]any))) {
				t.Fatal("envelope changed a renderer-admitted command operand")
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
