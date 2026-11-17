package agentenvelope

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func relationalOperandInput() Input {
	input := referenceIdentityInput(
		[]map[string]any{{"commandId": "command.one", "argv": []string{"tool", "--input", "inputs/source.json"}}},
		[]map[string]any{{"refId": "context.a", "kind": "path", "ref": "inputs/unrelated.json"}, {"refId": "context.z", "kind": "path", "ref": "inputs/source.json"}}, nil, nil,
	)
	input.ActionPlan[0]["commandIds"] = []any{"command.one"}
	input.OperandBindings = []OperandBinding{{CommandID: "command.one", ArgvIndex: 2, ContextRefID: "context.z"}}
	return input
}

func TestRelationalOrphanMetadataCoalescesOnlyWithAmbiguousOwner(t *testing.T) {
	for _, target := range []string{"command", "context", "receipt"} {
		for _, owner := range []string{"command", "context"} {
			for _, id := range []string{"shared", "renamed"} {
				t.Run(target+"/"+owner+"/"+id, func(t *testing.T) {
					input := roleAccountingInput(t, target, "shared", "shared")
					if owner == "command" {
						input.OperandBindings = []OperandBinding{{CommandID: id}, {CommandID: id}}
						input.CallerDisplayFallbackCommandIDs = []string{id, id}
					} else {
						input.ContextReferenceFields = []ContextReferenceField{{ContextRefID: id, Field: "path"}, {ContextRefID: id, Field: "path"}}
					}
					packet := Build(input)
					assertLocalIdentityAbsent(t, packet, "shared")
					assertOmission(t, packet, "proofkit.agent-envelope.omitted.ambiguousLocalIdentity", 1)
					want := 2
					if owner == target && id == "shared" {
						want = 1
					}
					assertIdentityDegraded(t, packet, want, 0)
					if want == 2 {
						assertOmission(t, packet, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 1)
					}
				})
			}
		}
	}
}

func TestRelationalLateValidationUsesPreparedBindingFacts(t *testing.T) {
	for _, mutation := range []string{"command", "context", "index", "field"} {
		t.Run(mutation, func(t *testing.T) {
			input := relationalOperandInput()
			prepared := prepareLocalReferences(input)
			retained, omitted := commandsWithRetainedOperandContexts(prepared.commands, prepared.contextRefs, prepared.operandContexts, prepared.callerDisplayFallbacks)
			if len(retained) != 1 || omitted != 0 {
				t.Fatal("fixture did not admit its command")
			}
			// Mutation is sequential, strictly after admission and before retention.
			switch mutation {
			case "command":
				input.OperandBindings[0].CommandID = "command.changed"
			case "context":
				input.OperandBindings[0].ContextRefID = "context.changed"
			case "index":
				input.OperandBindings[0].ArgvIndex = -1
			case "field":
				input.OperandBindings[0].ContextField = "changed"
			}
			retained, omitted = commandsWithRetainedOperandContexts(prepared.commands, prepared.contextRefs, prepared.operandContexts, prepared.callerDisplayFallbacks)
			if len(retained) != 1 || omitted != 0 {
				t.Error("caller slice mutation changed prepared command retention")
			}
			retained, omitted = commandsWithRetainedOperandContexts(prepared.commands, nil, prepared.operandContexts, prepared.callerDisplayFallbacks)
			if len(retained) != 0 || omitted != 1 {
				t.Error("loss of the admitted context did not remove its command")
			}
		})
	}
}

func TestRelationalContextPriorityIncludesAdmittedOperandDependencies(t *testing.T) {
	for _, redundantEvidence := range []bool{false, true} {
		for _, limit := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("evidence=%t/limit=%d", redundantEvidence, limit), func(t *testing.T) {
				input := relationalOperandInput()
				input.Bounds = map[string]any{"maxContextRefs": limit}
				if redundantEvidence {
					input.Commands[0]["evidenceRefs"] = []any{"context.z"}
				}
				packet := Build(input)
				commands, contexts := packet["commands"].([]any), packet["contextRefs"].([]any)
				ids := packet["actionPlan"].([]any)[0].(map[string]any)["commandIds"]
				if len(contexts) != limit {
					t.Fatal("declared context item limit changed")
				}
				if limit == 0 {
					if len(commands) != 0 || !reflect.DeepEqual(ids, []any{}) {
						t.Error("zero context budget retained an actionable command")
					}
					assertOmission(t, packet, "proofkit.agent-envelope.omitted.unavailableOperandContext", 1)
				} else {
					if len(commands) != 1 || !reflect.DeepEqual(ids, []any{"command.one"}) {
						t.Error("positive budget discarded the only required operand")
					} else if !reflect.DeepEqual(commands[0].(map[string]any)["argv"], []any{"tool", "--input", "inputs/source.json"}) {
						t.Error("retained command changed its exact argv")
					}
					if limit == 1 && contexts[0].(map[string]any)["refId"] != "context.z" {
						t.Error("unrelated context outranked the admitted dependency")
					}
				}
				wantOmissions := 2 - limit
				if limit == 0 {
					wantOmissions++
				}
				if packet["costContract"].(map[string]any)["omittedEdgeCount"] != wantOmissions {
					t.Error("dependency priority changed omission accounting")
				}
			})
		}
	}
}

func TestRelationalOnlySelectedAdmittedCommandsPrioritizeContexts(t *testing.T) {
	for _, scenario := range []string{"command capped", "binding rejected", "scalar fallback"} {
		t.Run(scenario, func(t *testing.T) {
			input := relationalOperandInput()
			input.Bounds = map[string]any{"maxContextRefs": 1}
			switch scenario {
			case "command capped":
				input.Bounds["maxCommandRefs"] = 0
			case "binding rejected", "scalar fallback":
				input.OperandBindings[0].ArgvIndex = -1
				if scenario == "scalar fallback" {
					input.CommandDisplayField = "command"
					input.Commands[0]["command"] = "caller supplied description"
					input.CallerDisplayFallbackCommandIDs = []string{"command.one"}
				}
			}
			packet := Build(input)
			if contexts := packet["contextRefs"].([]any); len(contexts) != 1 || contexts[0].(map[string]any)["refId"] != "context.a" {
				t.Error("unselected or unadmitted binding affected context priority")
			}
		})
	}
}

func TestRelationalEveryAdmittedContextRemainsRequired(t *testing.T) {
	for _, sameContext := range []bool{false, true} {
		for _, limit := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("same=%t/limit=%d", sameContext, limit), func(t *testing.T) {
				input := relationalOperandInput()
				input.ContextRefs[0] = map[string]any{"refId": "context.a", "path": "inputs/second.json"}
				input.ContextReferenceFields = []ContextReferenceField{{ContextRefID: "context.a", Field: "path"}}
				input.Commands[0]["argv"] = []string{"tool", "inputs/source.json", "inputs/second.json"}
				input.OperandBindings = []OperandBinding{
					{CommandID: "command.one", ArgvIndex: 1, ContextRefID: "context.z"},
					{CommandID: "command.one", ArgvIndex: 2, ContextRefID: "context.a", ContextField: "path"},
				}
				if sameContext {
					input.Commands[0]["argv"] = []string{"tool", "inputs/source.json", "inputs/source.json"}
					input.OperandBindings[1] = OperandBinding{CommandID: "command.one", ArgvIndex: 2, ContextRefID: "context.z"}
				}
				input.Bounds = map[string]any{"maxContextRefs": limit}
				packet := Build(input)
				wantRetained := limit == 2 || (sameContext && limit == 1)
				commands := packet["commands"].([]any)
				if (len(commands) == 1) != wantRetained {
					t.Error("command retention did not require every distinct admitted context")
				}
				if !wantRetained {
					assertOmission(t, packet, "proofkit.agent-envelope.omitted.unavailableOperandContext", 1)
				}
				if len(packet["contextRefs"].([]any)) != limit {
					t.Error("dependency fan-in changed the declared context limit")
				}
			})
		}
	}
}

func TestRelationalAdmittedLauncherKeepsItsExactEnvelopeArgv(t *testing.T) {
	for _, path := range []string{"/opt/caf\u00e9/\u65e5\u672c/bin/python", "/opt/task-validation/bin/python", "/opt/" + strings.Repeat("p", 513) + "/bin/python"} {
		renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, path)
		if err != nil {
			t.Fatal(err)
		}
		argv := renderer.Argv("self-check")
		packet := Build(Input{Renderer: renderer, CommandDisplayField: "command", Commands: []map[string]any{{"commandId": "command", "argv": argv, "command": renderer.DisplayCommand("self-check")}}})
		commands := packet["commands"].([]any)
		if len(commands) != 1 {
			t.Fatal("admitted launcher lost its envelope command")
		}
		command := commands[0].(map[string]any)
		assertAnyStrings(t, command["argv"], argv)
		if command["command"] != cliexec.DisplayArgv(argv) {
			t.Error("admitted launcher display lost exact argv identity")
		}
	}
}
