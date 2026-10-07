package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/changedpathset"
	"github.com/research-engineering/agentic-proofkit/internal/command/secretscan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

// This is registry ownership proof; independent CLI/schema cases own semantics.
func TestExplicitInputStructuresRetainEveryInvocationVariant(t *testing.T) {
	for _, item := range []struct {
		command, direction string
		schemas            []map[string]any
	}{
		{"changed-path-set", "input", []map[string]any{changedpathset.InputStructure()}},
		{"changed-path-set", "output", []map[string]any{changedpathset.OutputStructure(), changedpathset.EnvelopeStructure(), agentenvelope.InvalidInputStructure()}},
		{"secret-scan", "input", []map[string]any{secretscan.InputStructure()}},
		{"secret-scan", "output", []map[string]any{secretscan.OutputStructure()}},
	} {
		id := "proofkit." + item.command + "." + item.direction + ".v1.json-schema"
		t.Run(id, func(t *testing.T) {
			owner, ok := nativeStructureOwner(id)
			if !ok || owner.direction != item.direction || !slices.Equal(owner.commands, []string{item.command}) ||
				!slices.Equal(owner.predecessors, []string{"proofkit." + item.command + "." + item.direction + ".v1.root-shape"}) {
				t.Fatal("missing or incorrect exact consumer binding")
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
			if len(variants) != len(item.schemas) {
				t.Fatal("lost invocation variant")
			}
			for index, expected := range item.schemas {
				variant := variants[index].(map[string]any)
				if !reflect.DeepEqual(variant["schema"], expected) {
					t.Fatalf("variant%d differs from its native owner", index)
				}
			}
			if version, err := owner.contractVersion(definition); err != nil || version != "1" {
				t.Fatalf("version=%s error=%v", version, err)
			}
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
				t.Fatal(err)
			}
			variants[0].(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)["nonClaims"] = map[string]any{"type": "null"}
			delete(definition, "canonicalDigest")
			encoded, err := canonicalJSON(definition)
			if err != nil {
				t.Fatal(err)
			}
			definition["canonicalDigest"] = sha256Digest(encoded)
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err == nil {
				t.Fatal("rehashed foreign structure passed native owner admission")
			}
		})
	}
}
