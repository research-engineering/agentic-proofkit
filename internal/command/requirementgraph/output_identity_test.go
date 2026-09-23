package requirementgraph

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestOutputAdmissionPreservesOptionalSymbolIdentity(t *testing.T) {
	for _, level := range []string{"repository", "package", "module", "file", "symbol", "source_range"} {
		t.Run(level, func(t *testing.T) {
			input := graphPermutationInput(t)
			nodes := input["codeTopology"].(map[string]any)["nodes"].([]any)
			node := nodes[1].(map[string]any)
			if level == "repository" {
				node = nodes[0].(map[string]any)
			} else if level != "source_range" {
				node["abstractionLevel"] = level
				delete(node, "byteStart")
				delete(node, "byteEnd")
			}
			baseline, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []any{nil, "consumer.symbol", strings.Repeat("x", 256)} {
				node["symbolId"] = value
				output, err := Build(input)
				if err != nil {
					t.Fatalf("producer rejected supported symbol identity: %v", err)
				}
				wire := decodedGraphOutput(t, output)
				before := graphIdentityBytes(t, wire)
				admitted, err := AdmitOutput(wire, wire["snapshotId"].(string))
				if err != nil || !bytes.Equal(before, graphIdentityBytes(t, admitted)) {
					t.Fatalf("authentic output did not re-admit exactly: %v", err)
				}
				if !bytes.Equal(before, graphIdentityBytes(t, wire)) {
					t.Fatal("successful admission mutated its input")
				}
				if value == nil && !bytes.Equal(before, graphIdentityBytes(t, baseline)) {
					t.Fatal("null producer input changed absent-symbol output")
				}
			}
			for _, tc := range []struct {
				name  string
				value any
			}{
				{"null", nil}, {"number", json.Number("1")}, {"boolean", true},
				{"array", []any{}}, {"object", map[string]any{}}, {"empty", ""},
				{"invalid", "caller-private/id"}, {"padded", " consumer.symbol "},
				{"overlong", strings.Repeat("x", 257)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					wire := decodedGraphOutput(t, baseline)
					graphCodeNodeByKind(t, wire, level)["symbolId"] = tc.value
					before := graphIdentityBytes(t, wire)
					if _, err := AdmitOutput(wire, wire["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "symbolId") {
						t.Fatalf("counterfeit identity did not fail at symbolId: %v", err)
					} else if strings.Contains(err.Error(), "caller-private") {
						t.Fatal("identity admission disclosed caller text")
					}
					if !bytes.Equal(before, graphIdentityBytes(t, wire)) {
						t.Fatal("failed admission mutated its input")
					}
				})
			}
		})
	}
}

func graphIdentityBytes(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
