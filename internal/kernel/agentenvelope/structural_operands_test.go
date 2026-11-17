package agentenvelope

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestBuildPreservesCanonicalPathOperandsWithoutScalarExemptions(t *testing.T) {
	paths := []string{"inputs/task-requirements.json", "inputs/task-validation.json"}
	contexts := []map[string]any{
		{"refId": "proofkit.context.one", "kind": "path", "ref": paths[0]},
		{"refId": "proofkit.context.two", "kind": "path", "ref": paths[1]},
	}
	commands := []map[string]any{
		{"commandId": "proofkit.command.one", "argv": []any{"tool", "--input", paths[0]}},
		{"commandId": "proofkit.command.two", "argv": []string{"tool", "--input", paths[1]}},
	}
	bindings := []OperandBinding{
		{CommandID: "proofkit.command.one", ArgvIndex: 2, ContextRefID: "proofkit.context.one"},
		{CommandID: "proofkit.command.two", ArgvIndex: 2, ContextRefID: "proofkit.context.two"},
	}
	envelope := Build(Input{ContextRefs: contexts, Commands: commands, OperandBindings: bindings})
	refs := envelope["contextRefs"].([]any)
	gotCommands := envelope["commands"].([]any)
	if len(refs) != 2 || len(gotCommands) != 2 || len(envelope["omitted"].([]any)) != 0 {
		t.Fatal("canonical declared paths were lost")
	}
	for index, path := range paths {
		if refs[index].(map[string]any)["ref"] != path || gotCommands[index].(map[string]any)["argv"].([]any)[2] != path {
			t.Fatal("distinct canonical operands did not retain their exact identity")
		}
		if contexts[index]["ref"] != path {
			t.Fatal("path admission mutated caller context")
		}
	}
	if commands[0]["argv"].([]any)[2] != paths[0] || commands[1]["argv"].([]string)[2] != paths[1] {
		t.Fatal("argv admission mutated caller containers")
	}
	// A string that merely resembles the same file is not a declared path.
	contexts[0]["kind"] = "json_pointer"
	nearMiss := Build(Input{ContextRefs: contexts[:1], Commands: commands[:1], OperandBindings: bindings[:1]})
	if len(nearMiss["commands"].([]any)) != 0 || len(nearMiss["contextRefs"].([]any)) != 0 {
		t.Fatal("non-path text received the path-only admission policy")
	}
	assertOmission(t, nearMiss, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 2)
	contexts[0]["kind"] = "path"
	commands[0]["argv"] = []any{"tool", "--input", paths[0], paths[0]}
	unboundEqualText := Build(Input{ContextRefs: contexts[:1], Commands: commands[:1], OperandBindings: bindings[:1]})
	if len(unboundEqualText["commands"].([]any)) != 0 {
		t.Fatal("a different scalar argv position acquired a path role by text equality")
	}
	assertOmission(t, unboundEqualText, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 1)
}

func TestBuildBindsLauncherRoleToItsExactPosition(t *testing.T) {
	interpreter := "/opt/task-validation/bin/python"
	renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, interpreter)
	if err != nil {
		t.Fatal(err)
	}
	command := map[string]any{"commandId": "proofkit.command.one", "argv": []any{interpreter, "-m", "agentic_proofkit"}}
	envelope := Build(Input{Commands: []map[string]any{command}, Renderer: renderer})
	commands := envelope["commands"].([]any)
	if len(commands) != 1 || commands[0].(map[string]any)["argv"].([]any)[0] != interpreter {
		t.Fatal("renderer-admitted interpreter was not preserved")
	}
	for _, argv := range [][]any{
		{interpreter, "-m", "another_module"},
		{"tool", "--input", interpreter},
		{interpreter, 1, "agentic_proofkit"},
	} {
		refused := Build(Input{Commands: []map[string]any{{"commandId": "proofkit.command.one", "argv": argv}}, Renderer: renderer})
		if len(refused["commands"].([]any)) != 0 {
			t.Fatal("a different argv position or module inherited the launcher role")
		}
	}
}

func TestBuildRejectsInvalidPathOperandBindings(t *testing.T) {
	path := "inputs/task-requirements.json"
	command := map[string]any{"commandId": "proofkit.command.one", "argv": []any{"tool", "--input", path}}
	context := map[string]any{"refId": "proofkit.context.one", "kind": "path", "ref": path}
	binding := OperandBinding{CommandID: "proofkit.command.one", ArgvIndex: 2, ContextRefID: "proofkit.context.one"}
	for _, bad := range []OperandBinding{
		{CommandID: binding.CommandID, ArgvIndex: -1, ContextRefID: binding.ContextRefID},
		{CommandID: binding.CommandID, ArgvIndex: 3, ContextRefID: binding.ContextRefID},
		{CommandID: binding.CommandID, ArgvIndex: 0, ContextRefID: binding.ContextRefID},
		{CommandID: binding.CommandID, ArgvIndex: 2, ContextRefID: "proofkit.missing"},
		{CommandID: binding.CommandID, ArgvIndex: 2, ContextRefID: binding.ContextRefID, ContextField: "missing"},
	} {
		refused := Build(Input{ContextRefs: []map[string]any{context}, Commands: []map[string]any{command}, OperandBindings: []OperandBinding{bad}})
		if len(refused["commands"].([]any)) != 0 {
			t.Fatal("invalid operand binding retained a command")
		}
	}
	duplicate := Build(Input{ContextRefs: []map[string]any{context}, Commands: []map[string]any{command}, OperandBindings: []OperandBinding{binding, binding}})
	if len(duplicate["commands"].([]any)) != 0 {
		t.Fatal("duplicate operand roles were not refused")
	}
}

func TestBuildOmitsUnrepresentableArgvBeforeReferenceProjection(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A", 36)
	for _, argv := range []any{[]any{"tool", secret}, []string{"tool", secret}, []any{"tool", 1}, "not an argv array"} {
		input := referenceIdentityInput([]map[string]any{{"commandId": "proofkit.command.one", "argv": argv}}, nil, nil, nil)
		input.ActionPlan[0]["commandIds"] = []any{"proofkit.command.one"}
		envelope := Build(input)
		if len(envelope["commands"].([]any)) != 0 {
			t.Fatal("unsafe or unrepresentable argv survived as an executable marker")
		}
		action := envelope["actionPlan"].([]any)[0].(map[string]any)
		if len(action["commandIds"].([]any)) != 0 || envelope["costContract"].(map[string]any)["stopReason"] != "wide_or_full_gate_required" {
			t.Fatal("omitted command did not prune dependent references and escalate")
		}
		assertOmission(t, envelope, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 1)
		assertEnvelopeDoesNotContain(t, envelope, secret)
		assertEnvelopeDoesNotContain(t, envelope, "<redacted-diagnostic-value>")
	}
}
