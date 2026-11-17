package agentenvelope

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestBuildDerivesOnlyDeclaredCommandDisplayFromAdmittedArgv(t *testing.T) {
	renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, "/opt/task-validation/bin/python")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"command", "display"} {
		for _, path := range []string{"inputs/task-validation.json", "inputs/file with apostrophe's.json", "inputs/" + strings.Repeat("a", 600) + ".json"} {
			t.Run(field+"/"+path[:12], func(t *testing.T) {
				argv := renderer.Argv("witness-plan", "--input", path)
				want := cliexec.DisplayArgv(argv)
				original := map[string]any{"commandId": "proofkit.command.one", "argv": admit.StringSliceToAny(argv), field: "wrong display", "notes": want}
				input := Input{
					Renderer: renderer, CommandDisplayField: field,
					Commands:        []map[string]any{original, {"commandId": "proofkit.command.two", field: want}},
					ContextRefs:     []map[string]any{{"refId": "proofkit.context.one", "kind": "path", "ref": path}},
					OperandBindings: []OperandBinding{{CommandID: "proofkit.command.one", ArgvIndex: len(argv) - 1, ContextRefID: "proofkit.context.one"}},
				}
				packet := Build(input)
				commands := packet["commands"].([]any)
				if len(commands) != 2 || commands[0].(map[string]any)[field] != want {
					t.Fatal("declared generated display is not canonical")
				}
				if commands[0].(map[string]any)["notes"] != admit.RedactDiagnosticValue(want) || commands[1].(map[string]any)[field] != admit.RedactDiagnosticValue(want) {
					t.Fatal("equal caller text acquired generated display authority")
				}
				if original[field] != "wrong display" {
					t.Fatal("projection mutated caller map")
				}
				input.CommandDisplayField = ""
				if Build(input)["commands"].([]any)[0].(map[string]any)[field] != "wrong display" {
					t.Fatal("undeclared field was regenerated")
				}
				input.CommandDisplayField = "notes"
				if len(Build(input)["commands"].([]any)) != 1 {
					t.Fatal("unknown display role did not reject argv-bearing command")
				}
			})
		}
	}
}

func TestBuildRejectsSecretSignatureCreatedByCommandDisplayJoin(t *testing.T) {
	for _, token := range []string{"example000", "short"} {
		input := Input{CommandDisplayField: "display", Commands: []map[string]any{{
			"commandId": "proofkit.command.one", "argv": []any{"tool", "Bearer", token}, "display": "untrusted old display",
		}}}
		packet := Build(input)
		if token == "example000" {
			if len(packet["commands"].([]any)) != 0 {
				t.Fatal("safe operands assembled a secret-shaped display")
			}
			assertOmission(t, packet, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 1)
		} else if len(packet["commands"].([]any)) != 1 {
			t.Fatal("non-secret adjacent-word control was lost")
		}
	}
	packet := Build(Input{CommandDisplayField: "command", Commands: []map[string]any{{"commandId": "proofkit.command.one", "argv": []any{"tool"}}}})
	if _, created := packet["commands"].([]any)[0].(map[string]any)["command"]; created {
		t.Fatal("missing optional display was invented")
	}
}
