package requirementgraph

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestOutputAdmissionRequiresCanonicalEvidenceOrder(t *testing.T) {
	input := graphPermutationInput(t)
	topology := input["codeTopology"].(map[string]any)
	first := topology["edges"].([]any)[0].(map[string]any)
	first["evidenceRefs"] = []any{"consumer.trace.a", "consumer.trace.b"}
	topology["edges"] = []any{first}
	output, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	wire := decodedGraphOutput(t, output)
	before := graphIdentityBytes(t, wire)
	if _, err := AdmitOutput(wire, wire["snapshotId"].(string)); err != nil {
		t.Fatalf("authentic producer output did not re-admit: %v", err)
	}
	if !bytes.Equal(before, graphIdentityBytes(t, wire)) {
		t.Fatal("admission mutated the producer output")
	}

	var traced map[string]any
	for _, raw := range wire["edges"].([]any) {
		edge := raw.(map[string]any)
		if edge["edgeKind"] == "traced_to" {
			traced = edge
			break
		}
	}
	if traced == nil {
		t.Fatal("producer output lacks traced relation")
	}
	permuted := map[string]any{}
	for key, value := range traced {
		permuted[key] = value
	}
	permuted["evidenceRefs"] = []any{"consumer.trace.b", "consumer.trace.a"}
	permuted["edgeId"], err = semanticGraphID("code-edge", map[string]any{
		"authorityClass":   traced["authorityClass"],
		"codeNodeId":       strings.TrimPrefix(traced["toNodeId"].(string), "code:"),
		"currentnessState": traced["currentnessState"],
		"evidenceRefs":     permuted["evidenceRefs"],
		"requirementId":    strings.TrimPrefix(traced["fromNodeId"].(string), "requirement:"),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, duplicate := range []bool{false, true} {
		name := "single rehashed edge"
		if duplicate {
			name = "permutation pair"
		}
		t.Run(name, func(t *testing.T) {
			candidate := decodedGraphOutput(t, output)
			edges := candidate["edges"].([]any)
			if duplicate {
				edges = append(edges, permuted)
			} else {
				for index, raw := range edges {
					if raw.(map[string]any)["edgeId"] == traced["edgeId"] {
						edges[index] = permuted
						break
					}
				}
			}
			sort.Slice(edges, func(left, right int) bool {
				return edges[left].(map[string]any)["edgeId"].(string) < edges[right].(map[string]any)["edgeId"].(string)
			})
			candidate["edges"] = edges
			candidate["edgeCount"] = json.Number(strconv.Itoa(len(edges)))
			unchanged := graphIdentityBytes(t, candidate)
			if _, err := AdmitOutput(candidate, candidate["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "canonically sorted") {
				t.Fatalf("rehashed noncanonical relation was admitted: %v", err)
			}
			if !bytes.Equal(unchanged, graphIdentityBytes(t, candidate)) {
				t.Fatal("failed admission mutated the candidate")
			}
		})
	}
}
