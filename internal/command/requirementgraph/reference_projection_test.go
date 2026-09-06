package requirementgraph

import (
	"reflect"
	"testing"
)

func TestNodeReferencesPreserveTypedRecordAndFieldIdentity(t *testing.T) {
	node := map[string]any{"nodeId": "code.child", "parentNodeId": "code.parent", "sourceId": "not-a-node"}
	edge := map[string]any{"edgeId": "edge.observation", "codeNodeId": "code.child", "fromNodeId": "requirement.r", "toNodeId": "execution.e", "evidenceRefs": []any{"not-a-node"}}
	got := NodeReferences([]any{node}, []any{edge})
	want := []NodeReference{
		{"node", "code.child", "parentNodeId", "code.parent"},
		{"edge", "edge.observation", "codeNodeId", "code.child"},
		{"edge", "edge.observation", "fromNodeId", "requirement.r"},
		{"edge", "edge.observation", "toNodeId", "execution.e"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("typed references: %v", got)
	}
	node["parentNodeId"], edge["codeNodeId"] = "changed", "changed"
	if !reflect.DeepEqual(got, want) {
		t.Fatal("reference projection aliases the input")
	}
	if len(NodeReferences(nil, nil)) != 0 {
		t.Fatal("empty selection invented a reference")
	}
}
