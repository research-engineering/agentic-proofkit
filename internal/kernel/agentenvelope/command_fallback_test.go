package agentenvelope

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func fallbackInput() Input {
	path := "inputs/" + strings.Repeat("a", 550) + ".json"
	argv := []string{"tool", "--input", path}
	input := referenceIdentityInput([]map[string]any{{
		"commandId": "command.one", "command": cliexec.DisplayArgv(argv), "argv": argv,
	}}, []map[string]any{{"refId": "context.one", "kind": "path", "ref": path}}, nil, nil)
	input.CommandDisplayField = "command"
	input.CallerDisplayFallbackCommandIDs = []string{"command.one"}
	input.OperandBindings = []OperandBinding{{CommandID: "command.one", ArgvIndex: 2, ContextRefID: "context.one"}}
	input.ActionPlan[0]["commandIds"] = []any{"command.one"}
	return input
}

func TestCallerDisplayFallbackPreservesOnlyItsIndependentScalarOrigin(t *testing.T) {
	for _, phase := range []string{"retained", "bounded context", "invalid context"} {
		t.Run(phase, func(t *testing.T) {
			input := fallbackInput()
			original := input.Commands[0]["command"].(string)
			switch phase {
			case "bounded context":
				input.Bounds = map[string]any{"maxContextRefs": 0}
			case "invalid context":
				input.ContextRefs[0]["ref"] = "inputs/unsafe\u202e.json"
			}
			envelope := Build(input)
			commands := envelope["commands"].([]any)
			if len(commands) != 1 {
				t.Fatalf("independent caller origin lost: %d commands", len(commands))
			}
			command := commands[0].(map[string]any)
			if command["commandId"] != "command.one" {
				t.Fatal("fallback changed its local identity")
			}
			if phase == "retained" {
				if command["command"] != original || !reflect.DeepEqual(command["argv"], []any{"tool", "--input", input.ContextRefs[0]["ref"]}) {
					t.Fatal("retained structural command was scalar-truncated")
				}
			} else {
				if _, typed := command["argv"]; typed || command["command"] != sanitizeValue(original) || command["command"] == original {
					t.Fatal("fallback did not restore the original bounded scalar, without argv")
				}
				kind, count := "unavailableOperandContext", 1
				if phase == "invalid context" {
					kind, count = "unsafeStructuralOperand", 2
				}
				assertOmission(t, envelope, "proofkit.agent-envelope.omitted."+kind, count)
			}
			if ids := envelope["actionPlan"].([]any)[0].(map[string]any)["commandIds"]; !reflect.DeepEqual(ids, []any{"command.one"}) {
				t.Fatal("retained caller command lost its action reference")
			}
			if envelope["bounds"].(map[string]any)["prunedLocalReferenceCount"] != nil {
				t.Fatal("scalar downgrade incorrectly reported a removed local command")
			}
			if input.Commands[0]["command"] != original || input.Commands[0]["argv"] == nil {
				t.Fatal("fallback admission mutated the input")
			}
		})
	}
}

func TestCallerFallbackCannotResurrectAbsentOrUnadmittedCommands(t *testing.T) {
	for _, scenario := range []string{"no caller", "bounded command", "ambiguous identity", "unsafe identity"} {
		t.Run(scenario, func(t *testing.T) {
			input := fallbackInput()
			input.Bounds = map[string]any{"maxContextRefs": 0}
			switch scenario {
			case "no caller":
				input.CallerDisplayFallbackCommandIDs = nil
			case "bounded command":
				input.Bounds["maxCommandRefs"] = 0
			case "ambiguous identity":
				input.Commands = append(input.Commands, input.Commands[0])
			case "unsafe identity":
				input.Commands[0]["commandId"] = "invalid identity"
				input.CallerDisplayFallbackCommandIDs = []string{"invalid identity"}
			}
			if commands := Build(input)["commands"].([]any); len(commands) != 0 {
				t.Fatal("caller fallback resurrected an unavailable command")
			}
		})
	}
}

func TestCallerFallbackMetadataCoalescesOrphansWithoutPoisoningContext(t *testing.T) {
	input := fallbackInput()
	input.CallerDisplayFallbackCommandIDs = append(input.CallerDisplayFallbackCommandIDs, "missing.command", "missing.command", "context.one")
	input.OperandBindings = append(input.OperandBindings, OperandBinding{CommandID: "missing.command", ArgvIndex: 1, ContextRefID: "context.one"})
	envelope := Build(input)
	if len(envelope["commands"].([]any)) != 1 || len(envelope["contextRefs"].([]any)) != 1 {
		t.Fatal("orphan command metadata poisoned an independent target")
	}
	assertOmission(t, envelope, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 2)
	input = fallbackInput()
	delete(input.Commands[0], "argv")
	input.OperandBindings = nil
	if command := Build(input)["commands"].([]any)[0].(map[string]any); command["argv"] != nil || command["command"] != sanitizeValue(input.Commands[0]["command"].(string)) {
		t.Fatal("caller text acquired a structural role without argv")
	}
}
