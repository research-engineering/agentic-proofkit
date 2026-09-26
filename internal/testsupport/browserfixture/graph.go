package browserfixture

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// GraphLayoutWorkspace keeps an admitted parent after both children in lexical
// order. The mixed variant retains native cross-plane and parallel relations.
func GraphLayoutWorkspace(mixed bool) (map[string]any, error) {
	workspace, err := Workspace()
	if err != nil {
		return nil, err
	}
	context := workspace["context"].(map[string]any)
	projections := context["projections"].(map[string]any)
	tree := projections["specTree"].(map[string]any)
	root := tree["nodes"].([]any)[0].(map[string]any)
	root["nodeId"], root["label"] = "z", "Parent Z"
	nodes := []any{root}
	for index, id := range []string{"a", "b"} {
		nodes = append(nodes, map[string]any{
			"nodeId": id, "nodeKind": "module_spec", "label": "Child " + id,
			"displayOrder": json.Number(fmt.Sprint(index + 2)), "callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{"sourceRefId": id + ".overview", "sourceRefKind": "source_id", "sourceRole": "overview", "sourceId": "browser.fixture.requirements"}},
		})
	}
	tree["rootNodeId"], tree["nodes"] = "z", nodes
	tree["edges"] = []any{map[string]any{"parentNodeId": "z", "childNodeId": "a"}, map[string]any{"parentNodeId": "z", "childNodeId": "b"}}
	admitted, err := requirementspectree.Evaluate(tree)
	if err != nil || admitted.ExitCode != 0 {
		return nil, fmt.Errorf("graph layout fixture tree is invalid")
	}
	projections["specTree"] = requirementspectree.TreeValue(admitted.Tree)
	treeBytes, err := stablejson.Marshal(projections["specTree"])
	if err != nil {
		return nil, err
	}
	identitySources := []any{}
	for _, raw := range context["sources"].([]any) {
		source := raw.(map[string]any)
		if source["kind"] == "requirement_source" {
			source["nodeId"] = "z"
		}
		if source["kind"] == "spec_tree" {
			source["currentDigest"] = digest.SHA256TextRef(string(treeBytes))
		}
		identity := maps.Clone(source)
		identity["expectedDigest"] = ""
		identitySources = append(identitySources, identity)
	}
	encoded, err := stablejson.Marshal(map[string]any{"catalogId": context["catalogId"], "projections": projections, "sources": identitySources})
	if err != nil {
		return nil, err
	}
	context["snapshotId"] = digest.SHA256TextRef(string(encoded))
	delete(workspace, "diffInput")
	graph := workspace["graphInput"].(map[string]any)
	graph["context"] = context
	if !mixed {
		delete(graph, "codeTopology")
		delete(graph, "codeSources")
	}
	return workspace, nil
}

func GraphNumericWorkspace() (map[string]any, error) {
	workspace, err := Workspace()
	if err != nil {
		return nil, err
	}
	graph := workspace["graphInput"].(map[string]any)
	delete(graph, "codeSources")
	for _, raw := range graph["codeTopology"].(map[string]any)["nodes"].([]any) {
		node := raw.(map[string]any)
		if node["abstractionLevel"] == "source_range" {
			node["byteStart"] = json.Number("9007199254740992")
			node["byteEnd"] = json.Number("9007199254740993")
			node["currentnessState"] = "unverified"
		}
	}
	return workspace, nil
}

// GraphCapacityWorkspace permits a native 64-primary, 128-boundary window.
// The selected requirements each have two distinct caller-reported records.
func GraphCapacityWorkspace() (map[string]any, error) {
	workspace, err := LookupWorkspace()
	if err != nil {
		return nil, err
	}
	base, err := Workspace()
	if err != nil {
		return nil, err
	}
	graph := base["graphInput"].(map[string]any)
	graph["context"] = workspace["context"]
	topology := graph["codeTopology"].(map[string]any)
	topology["edges"] = []any{}
	coverage := make([]any, 0, 128)
	for index := range 64 {
		requirementID := "REQ-A"
		if index > 0 {
			requirementID = fmt.Sprintf("REQ-B-%03d", index-1)
		}
		for ordinal := range 2 {
			coverage = append(coverage, map[string]any{
				"authorityClass": "caller_reported", "codeNodeId": "code.retry",
				"currentnessState": "unverified", "evidenceRef": fmt.Sprintf("capacity.evidence.%03d.%d", index, ordinal),
				"producerId": "capacity.runner", "requirementId": requirementID, "state": "failed",
			})
		}
	}
	topology["nativeCoverage"] = coverage
	workspace["graphInput"] = graph
	return workspace, nil
}
