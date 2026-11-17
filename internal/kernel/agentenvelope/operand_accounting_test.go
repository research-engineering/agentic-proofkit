package agentenvelope

import (
	"fmt"
	"strings"
	"testing"
)

func TestOperandMetadataDoesNotRecountRejectedTargets(t *testing.T) {
	for _, fields := range []int{1, 3} {
		id := strings.Repeat("a", 256) + ".context"
		context := map[string]any{"refId": id}
		declarations := []ContextReferenceField{}
		for index := range fields {
			field := fmt.Sprintf("path%d", index)
			context[field] = "inputs/source.json"
			declarations = append(declarations, ContextReferenceField{ContextRefID: id, Field: field})
		}
		packet := Build(Input{ContextRefs: []map[string]any{context}, ContextReferenceFields: declarations})
		if len(packet["contextRefs"].([]any)) != 0 || packet["costContract"].(map[string]any)["omittedEdgeCount"] != 1 {
			t.Fatalf("%d declarations recounted a rejected context: %v", fields, packet["costContract"])
		}
		assertOmission(t, packet, "proofkit.agent-envelope.omitted.unsafeLocalIdentity", 1)
		bindings := []OperandBinding{}
		for index := range fields {
			bindings = append(bindings, OperandBinding{CommandID: id, ArgvIndex: index, ContextRefID: "proofkit.missing"})
		}
		packet = Build(Input{Commands: []map[string]any{{"commandId": id, "argv": []any{"tool"}}}, OperandBindings: bindings})
		if len(packet["commands"].([]any)) != 0 || packet["costContract"].(map[string]any)["omittedEdgeCount"] != 1 {
			t.Fatalf("%d bindings recounted a rejected command: %v", fields, packet["costContract"])
		}
		assertOmission(t, packet, "proofkit.agent-envelope.omitted.unsafeLocalIdentity", 1)
	}
}

func TestOperandMetadataRetainsUnknownTargetAndAmbiguityAccounting(t *testing.T) {
	fields := []ContextReferenceField{{ContextRefID: "proofkit.context", Field: "path"}, {ContextRefID: "proofkit.context", Field: "selector"}}
	for _, contexts := range [][]map[string]any{
		nil,
		{{"refId": "proofkit.context", "path": "a", "selector": "a"}, {"refId": "proofkit.context", "path": "b", "selector": "b"}},
	} {
		packet := Build(Input{ContextRefs: contexts, ContextReferenceFields: fields})
		if len(packet["contextRefs"].([]any)) != 0 || packet["costContract"].(map[string]any)["omittedEdgeCount"] != 1 {
			t.Fatalf("unknown or ambiguous context accounting changed: %v", packet["costContract"])
		}
	}
	packet := Build(Input{OperandBindings: []OperandBinding{
		{CommandID: "proofkit.missing", ArgvIndex: 1}, {CommandID: "proofkit.missing", ArgvIndex: 2},
	}})
	if packet["costContract"].(map[string]any)["omittedEdgeCount"] != 1 {
		t.Fatalf("unknown command accounting changed: %v", packet["costContract"])
	}
}
