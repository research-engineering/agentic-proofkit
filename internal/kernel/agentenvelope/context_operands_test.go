package agentenvelope

import (
	"strings"
	"testing"
)

func TestBuildPreservesOnlyDeclaredStructuralReferenceFields(t *testing.T) {
	first, second := strings.Repeat("d/", 300)+"a.json", strings.Repeat("d/", 300)+"b.json"
	contexts := []map[string]any{
		{"refId": "proofkit.context.one", "path": first, "selector": first},
		{"refId": "proofkit.context.two", "path": second, "selector": second},
	}
	fields := []ContextReferenceField{}
	for _, id := range []string{"proofkit.context.one", "proofkit.context.two"} {
		fields = append(fields, ContextReferenceField{ContextRefID: id, Field: "path"}, ContextReferenceField{ContextRefID: id, Field: "selector"})
	}
	envelope := Build(Input{ContextRefs: contexts, ContextReferenceFields: fields})
	refs := envelope["contextRefs"].([]any)
	if len(refs) != 2 || refs[0].(map[string]any)["path"] != first || refs[1].(map[string]any)["path"] != second || refs[0].(map[string]any)["selector"] != first {
		t.Fatal("distinct structural references were changed or merged")
	}
	if contexts[0]["path"] != first {
		t.Fatal("reference preparation mutated caller input")
	}
	unregistered := Build(Input{ContextRefs: contexts})
	if unregistered["contextRefs"].([]any)[0].(map[string]any)["path"] == first {
		t.Fatal("arbitrary field name acquired a structural role")
	}
}

func TestBuildRejectsEntireContextBeforeAuthorizingItsOperands(t *testing.T) {
	path := "inputs/task-requirements.json"
	secret := "prefixghp_" + strings.Repeat("A", 36) + "suffix.json"
	context := map[string]any{"refId": "proofkit.context.one", "path": path, "selector": secret}
	envelope := Build(Input{
		ContextRefs:            []map[string]any{context},
		ContextReferenceFields: []ContextReferenceField{{ContextRefID: "proofkit.context.one", Field: "path"}, {ContextRefID: "proofkit.context.one", Field: "selector"}},
		Commands:               []map[string]any{{"commandId": "proofkit.command.one", "argv": []any{"tool", "--input", path}}},
		OperandBindings:        []OperandBinding{{CommandID: "proofkit.command.one", ArgvIndex: 2, ContextRefID: "proofkit.context.one", ContextField: "path"}},
	})
	if len(envelope["commands"].([]any)) != 0 || len(envelope["contextRefs"].([]any)) != 0 {
		t.Fatal("a rejected sibling field still authorized a command path")
	}
	assertOmission(t, envelope, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 2)
	assertEnvelopeDoesNotContain(t, envelope, secret)
}

func TestBuildDropsCommandsWhenTheirOperandContextIsOmitted(t *testing.T) {
	input := referenceIdentityInput(
		[]map[string]any{{"commandId": "proofkit.command.one", "argv": []any{"tool", "--input", "inputs/source.json"}}},
		[]map[string]any{{"refId": "proofkit.context.one", "kind": "path", "ref": "inputs/source.json"}}, nil, nil,
	)
	input.ActionPlan[0]["commandIds"] = []any{"proofkit.command.one"}
	input.Bounds = map[string]any{"maxContextRefs": 0}
	input.OperandBindings = []OperandBinding{{CommandID: "proofkit.command.one", ArgvIndex: 2, ContextRefID: "proofkit.context.one"}}
	envelope := Build(input)
	if len(envelope["commands"].([]any)) != 0 || len(envelope["actionPlan"].([]any)[0].(map[string]any)["commandIds"].([]any)) != 0 {
		t.Fatal("command survived loss of its required operand context")
	}
	if envelope["costContract"].(map[string]any)["stopReason"] != "wide_or_full_gate_required" {
		t.Fatal("operand loss did not stop continuation")
	}
}
