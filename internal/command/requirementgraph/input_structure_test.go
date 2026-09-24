package requirementgraph

import (
	"encoding/json"
	"testing"
)

func TestGraphInputStructurePreservesOptionalAndNumericDomains(t *testing.T) {
	for _, mode := range []string{"complete", "absent", "null", "negative-zero", "generated-int", "nullable-node-fields"} {
		t.Run(mode, func(t *testing.T) {
			input := graphPermutationInput(t)
			nodes := input["codeTopology"].(map[string]any)["nodes"].([]any)
			switch mode {
			case "absent":
				delete(input, "codeSources")
				delete(input, "codeTopology")
			case "null":
				input["codeSources"], input["codeTopology"] = nil, nil
			case "negative-zero":
				nodes[1].(map[string]any)["byteStart"] = json.Number("-0")
			case "generated-int":
				nodes[1].(map[string]any)["byteStart"] = 0
			case "nullable-node-fields":
				for _, key := range []string{"parentNodeId", "symbolId", "byteStart", "byteEnd"} {
					nodes[0].(map[string]any)[key] = nil
				}
			}
			if err := graphInputShape.CheckGenerated(input, "graph"); err != nil {
				t.Fatal(err)
			}
			output, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AdmitOutput(decodedGraphOutput(t, output), input["context"].(map[string]any)["snapshotId"].(string)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGraphInputStructureRejectsEvidenceAndRangeVariantConfusion(t *testing.T) {
	for _, mutation := range []string{"missing-content", "topology-id", "null-nodes", "missing-start", "range-on-repository", "wrong-authority", "unknown-execution-field", "empty-edge-evidence"} {
		t.Run(mutation, func(t *testing.T) {
			input := graphPermutationInput(t)
			topology := input["codeTopology"].(map[string]any)
			nodes := topology["nodes"].([]any)
			switch mutation {
			case "missing-content":
				delete(input["codeSources"].([]any)[0].(map[string]any), "content")
			case "topology-id":
				topology["topologyId"] = "ignored.identity"
			case "null-nodes":
				topology["nodes"] = nil
			case "missing-start":
				delete(nodes[1].(map[string]any), "byteStart")
			case "range-on-repository":
				nodes[0].(map[string]any)["byteStart"] = json.Number("0")
			case "wrong-authority":
				topology["nativeCoverage"].([]any)[0].(map[string]any)["authorityClass"] = "owner_admitted"
			case "unknown-execution-field":
				topology["nativeCoverage"].([]any)[0].(map[string]any)["approved"] = true
			case "empty-edge-evidence":
				topology["edges"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{}
			}
			if err := graphInputShape.CheckGenerated(input, "graph"); err == nil {
				t.Fatal("invalid graph structure admitted")
			}
			if _, err := Build(input); err == nil {
				t.Fatal("native graph accepted structural confusion")
			}
		})
	}
}
