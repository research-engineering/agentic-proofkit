package requirementbrowser

import (
	"maps"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

func TestGraphWindowDistinguishesOffPageParentsWithoutInferringEdges(t *testing.T) {
	input, err := browserfixture.Workspace()
	if err != nil {
		t.Fatal(err)
	}
	topology := input["graphInput"].(map[string]any)["codeTopology"].(map[string]any)
	nodes := topology["nodes"].([]any)
	file := maps.Clone(nodes[0].(map[string]any))
	file["nodeId"], file["parentNodeId"], file["abstractionLevel"] = "code.file", "code.repository", "file"
	symbol := maps.Clone(file)
	symbol["nodeId"], symbol["parentNodeId"], symbol["abstractionLevel"] = "code.symbol", "code.file", "symbol"
	nodes[1].(map[string]any)["parentNodeId"] = "code.symbol"
	topology["nodes"] = append(nodes, file, symbol)
	session, _, err := buildWorkspace(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"code:code.retry", "code:code.symbol"}, {"code:code.symbol", "code:code.file"}, {"code:code.file", "code:code.repository"}} {
		page, _ := graphWindow(session.Graph, projectionQuery{Offset: graphNodeOffset(t, session.Graph, pair[0]), MaxRecords: 1, MaxEdges: 1, EdgeOffset: 80_000})
		if !reflect.DeepEqual(page["primaryNodeIds"], []any{pair[0]}) || page["selectedNodeCount"] != 1 || page["selectedEdgeCount"] != 0 || page["boundaryNodeCount"] != 0 {
			t.Fatal("parent reference expanded endpoint selection")
		}
		refs := page["references"].([]any)
		if len(refs) != 1 {
			t.Fatalf("parent reference count %d", len(refs))
		}
		ref := refs[0].(map[string]any)
		want := map[string]any{"disposition": "outside_page", "field": "parentNodeId", "recordId": pair[0], "recordKind": "node", "targetNodeId": pair[1], "targetOffset": graphNodeOffset(t, session.Graph, pair[1])}
		if !reflect.DeepEqual(ref, want) {
			t.Fatalf("parent disposition: %v", ref)
		}
		followed, _ := graphWindow(session.Graph, projectionQuery{Offset: ref["targetOffset"].(int), MaxRecords: 1, MaxEdges: 1})
		if !reflect.DeepEqual(followed["primaryNodeIds"], []any{pair[1]}) {
			t.Fatal("follow offset opened a different target")
		}
	}
}

func TestGraphWindowKeepsAuxiliaryCodeTargetSeparateFromEndpoints(t *testing.T) {
	input, err := browserfixture.Workspace()
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := buildWorkspace(input)
	if err != nil {
		t.Fatal(err)
	}
	primary := "requirement:REQ-CONSUMER-001"
	incidentOffset := 0
	for _, raw := range session.Graph["edges"].([]any) {
		edge := raw.(map[string]any)
		if edge["fromNodeId"] != primary && edge["toNodeId"] != primary {
			continue
		}
		if edge["edgeKind"] != "observed_by" {
			incidentOffset++
			continue
		}
		page, _ := graphWindow(session.Graph, projectionQuery{Offset: graphNodeOffset(t, session.Graph, primary), MaxRecords: 1, MaxEdges: 1, EdgeOffset: incidentOffset})
		assertWorkspaceRowIDs(t, page["edges"], "edgeId", []string{edge["edgeId"].(string)})
		if !reflect.DeepEqual(page["primaryNodeIds"], []any{primary}) || page["boundaryNodeCount"] != 1 || page["selectedNodeCount"] != 2 {
			t.Fatal("auxiliary reference changed endpoint closure")
		}
		seen := map[string]bool{}
		for _, rawRef := range page["references"].([]any) {
			ref := rawRef.(map[string]any)
			field := ref["field"].(string)
			seen[field] = true
			wantDisposition := "included"
			if field == "codeNodeId" {
				wantDisposition = "outside_page"
			}
			if ref["recordId"] != edge["edgeId"] || ref["recordKind"] != "edge" || ref["targetNodeId"] != edge[field] || ref["disposition"] != wantDisposition || ref["targetOffset"] != graphNodeOffset(t, session.Graph, edge[field].(string)) {
				t.Fatal("edge reference lost record, field, target or disposition")
			}
		}
		if !reflect.DeepEqual(seen, map[string]bool{"codeNodeId": true, "fromNodeId": true, "toNodeId": true}) {
			t.Fatal("edge reference field closure is incomplete")
		}
		return
	}
	t.Fatal("authored observation fixture is missing")
}

func graphNodeOffset(t *testing.T, graph map[string]any, id string) int {
	t.Helper()
	for offset, raw := range graph["nodes"].([]any) {
		if raw.(map[string]any)["nodeId"] == id {
			return offset
		}
	}
	t.Fatalf("fixture target %s is absent", id)
	return 0
}
