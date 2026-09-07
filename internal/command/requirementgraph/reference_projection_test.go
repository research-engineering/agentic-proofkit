package requirementgraph

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
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

func TestGraphDigestNodeAndEndpointAdmissionAgree(t *testing.T) {
	const proofID = "proof:5d8cdbfd0739d25ae297840d1514765c4db00ac02cd521669535b5865cffc0fe"
	const requirementID = "REQ-WIRE-001"
	identity := map[string]any{"requirementId": requirementID, "scenarioId": "collection.scenario.001", "witnessId": "collection.witness.001", "witnessKind": "contract", "witnessPath": "tests/collection_test.go"}
	hashID := func(prefix string, value any) string {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%s:%x", prefix, sha256.Sum256(append(encoded, '\n')))
	}
	if proofID != hashID("proof", identity) {
		t.Fatal("independent proof-node identity fixture changed")
	}
	if _, err := admit.RuleID(proofID, "caller id"); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatal("counterexample does not exercise digest/caller-identity separation")
	}
	proofNode := map[string]any{"nodeId": proofID, "kind": "scenario", "evidencePlane": "proof_coverage", "sourceId": "collection.witness.001", "label": "collection.scenario.001"}
	for key, value := range identity {
		proofNode[key] = value
	}
	edge := map[string]any{"edgeKind": "proved_by_candidate", "evidencePlane": "proof_coverage", "fromNodeId": "requirement:" + requirementID, "toNodeId": proofID}
	edge["edgeId"] = hashID("proof-edge", map[string]any{"fromNodeId": edge["fromNodeId"], "toNodeId": edge["toNodeId"]})
	output := map[string]any{
		"schemaVersion": json.Number("1"), "graphKind": "proofkit.requirement-traceability-graph", "graphId": "fixture.graph", "snapshotId": "sha256:" + strings.Repeat("a", 64),
		"nodeCount": json.Number("2"), "edgeCount": json.Number("1"), "edges": []any{edge},
		"nodes":     []any{proofNode, map[string]any{"nodeId": "requirement:" + requirementID, "kind": "requirement", "evidencePlane": "specification_coverage", "sourceId": requirementID, "label": requirementID}},
		"nonClaims": []any{"Traceability graph is a derived projection and does not infer code topology, native execution coverage, proof freshness, merge, release, or rollout readiness.", "Specification, proof, code traceability, and native execution remain distinct evidence planes."},
	}
	if err := admitGraphNode(proofNode); err != nil {
		t.Fatalf("digest node itself is invalid: %v", err)
	}
	decoded := decodedGraphOutput(t, output)
	if _, err := AdmitOutput(decoded, output["snapshotId"].(string)); err != nil {
		t.Fatalf("resolved digest endpoint did not survive wire admission: %v", err)
	}
	edge["toNodeId"] = "proof:" + strings.Repeat("b", 64)
	edge["edgeId"] = hashID("proof-edge", map[string]any{"fromNodeId": edge["fromNodeId"], "toNodeId": edge["toNodeId"]})
	if _, err := AdmitOutput(output, output["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "target must resolve") {
		t.Fatalf("unmatched but well-formed digest endpoint was accepted or masked: %v", err)
	}
	if _, err := admitGraphID("code:20260901", "caller node"); err == nil {
		t.Fatal("digest support relaxed ordinary caller identity admission")
	}
}

func TestTransparentGraphIdentitiesPreserveComponentBounds(t *testing.T) {
	for _, prefix := range []string{"spec", "requirement", "code", "execution"} {
		value := prefix + ":" + strings.Repeat("A", 256)
		if actual, err := admitGraphID(value, "derived identity"); err != nil || actual != value {
			t.Errorf("%s rejected an admitted component: %v", prefix, err)
		}
		for _, component := range []string{"", strings.Repeat("A", 257), "20260901", "A/unsafe", "A\nunsafe"} {
			if _, err := admitGraphID(prefix+":"+component, "derived identity"); err == nil {
				t.Errorf("%s accepted an invalid component", prefix)
			}
		}
	}
	input := graphPermutationInput(t)
	topology := input["codeTopology"].(map[string]any)
	nodes := topology["nodes"].([]any)
	parent, child := strings.Repeat("A", 256), strings.Repeat("B", 256)
	nodes[0].(map[string]any)["nodeId"] = parent
	nodes[1].(map[string]any)["nodeId"], nodes[1].(map[string]any)["parentNodeId"] = child, parent
	for _, raw := range topology["edges"].([]any) {
		raw.(map[string]any)["codeNodeId"] = child
	}
	for index, raw := range topology["nativeCoverage"].([]any) {
		raw.(map[string]any)["codeNodeId"] = child
		raw.(map[string]any)["evidenceRef"] = strings.Repeat(string(rune('C'+index)), 256)
	}
	output, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	wire := decodedGraphOutput(t, output)
	if _, err := AdmitOutput(wire, wire["snapshotId"].(string)); err != nil {
		t.Fatalf("long code and native references failed wire admission: %v", err)
	}
	seen := map[string]bool{}
	for _, raw := range wire["nodes"].([]any) {
		seen[raw.(map[string]any)["nodeId"].(string)] = true
	}
	for _, expected := range []string{"code:" + parent, "code:" + child, "execution:" + strings.Repeat("C", 256), "execution:" + strings.Repeat("D", 256)} {
		if !seen[expected] {
			t.Fatal("graph replaced a caller-owned component identity")
		}
	}
}
