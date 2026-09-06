package browserfixture

import (
	"encoding/json"
	"fmt"
)

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
