package requirementbrowser

import (
	"maps"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

func TestGraphLayoutFixtureAdmitsExactNativeRelations(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "minimal"
		wantNodes, wantEdges := 4, 3
		if mixed {
			name, wantNodes, wantEdges = "mixed", 8, 8
		}
		t.Run(name, func(t *testing.T) {
			input, err := browserfixture.GraphLayoutWorkspace(mixed)
			if err != nil {
				t.Fatal(err)
			}
			session, _, err := buildWorkspace(input)
			if err != nil {
				t.Fatal(err)
			}
			page, state := graphWindow(session.Graph, projectionQuery{MaxRecords: 64, MaxEdges: 128})
			if state != "complete" || page["selectedNodeCount"] != wantNodes || page["selectedEdgeCount"] != wantEdges || page["boundaryNodeCount"] != 0 {
				t.Fatal("native layout fixture lost its compact complete page")
			}
			want := map[string]any{
				"edgeId":   "spec-edge:8b5fd51688cd41c917a84d10b0caa618a65322556db337d35fe218a345ed89ee",
				"edgeKind": "contains", "evidencePlane": "specification_coverage", "fromNodeId": "spec:z", "toNodeId": "spec:a",
			}
			found, children, traces, observations := false, 0, map[string]bool{}, 0
			for _, raw := range page["edges"].([]any) {
				edge := raw.(map[string]any)
				if edge["fromNodeId"] == edge["toNodeId"] {
					t.Fatal("layout witness unexpectedly contains a self-loop")
				}
				if edge["edgeId"] == want["edgeId"] {
					found = reflect.DeepEqual(edge, want)
				}
				if edge["fromNodeId"] == "spec:z" && edge["edgeKind"] == "contains" && (edge["toNodeId"] == "spec:a" || edge["toNodeId"] == "spec:b") {
					children++
				}
				if edge["fromNodeId"] == "requirement:REQ-CONSUMER-001" && edge["toNodeId"] == "code:code.retry" && edge["edgeKind"] == "traced_to" {
					traces[edge["edgeId"].(string)] = true
				}
				if edge["fromNodeId"] == "requirement:REQ-CONSUMER-001" && edge["edgeKind"] == "observed_by" && edge["codeNodeId"] == "code:code.retry" {
					observations++
				}
			}
			if !found || children != 2 || graphNodeOffset(t, session.Graph, "spec:a") >= graphNodeOffset(t, session.Graph, "spec:b") || graphNodeOffset(t, session.Graph, "spec:b") >= graphNodeOffset(t, session.Graph, "spec:z") {
				t.Fatal("native parent-to-child relation or lexical obstruction changed")
			}
			if mixed && (len(traces) != 2 || observations != 2) {
				t.Fatal("mixed fixture lost distinct parallel or skip-plane relations")
			}
		})
	}
}

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
