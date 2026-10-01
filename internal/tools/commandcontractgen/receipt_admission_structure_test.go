package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
)

func TestReceiptNativeStructuresRejectRehashedNestedDrift(t *testing.T) {
	for _, command := range []string{"proof-receipt-admission", "receipt-producer-admission"} {
		for _, direction := range []string{"input", "output"} {
			id := "proofkit." + command + "." + direction + ".v1.json-schema"
			index := slices.IndexFunc(nativeStructures(), func(owner nativeStructure) bool { return owner.id == id })
			if index < 0 {
				t.Fatalf("missing owner %s", id)
			}
			owner := nativeStructures()[index]
			if owner.direction != direction || !slices.Equal(owner.commands, []string{command}) || !slices.Equal(owner.predecessors, []string{"proofkit." + command + "." + direction + ".v1.root-shape"}) {
				t.Fatal("wrong exact native binding")
			}
			row, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			variant := row["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
			var expected map[string]any
			if command == "proof-receipt-admission" {
				if direction == "input" {
					expected = proofreceiptadmission.InputStructure()
				} else {
					expected = proofreceiptadmission.OutputStructure()
				}
			} else {
				if direction == "input" {
					expected = receiptproduceradmission.InputStructure()
				} else {
					expected = receiptproduceradmission.OutputStructure()
				}
			}
			if !reflect.DeepEqual(variant["schema"], expected) {
				t.Fatal("schema is not native-owned")
			}
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{row}}); err != nil {
				t.Fatal(err)
			}
			variant["schema"].(map[string]any)["properties"].(map[string]any)["nonClaims"].(map[string]any)["items"] = map[string]any{"type": "boolean"}
			delete(row, "canonicalDigest")
			encoded, err := canonicalJSON(row)
			if err != nil {
				t.Fatal(err)
			}
			row["canonicalDigest"] = sha256Digest(encoded)
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{row}}); err == nil {
				t.Fatal("coherently rehashed nested drift was admitted")
			}
		}
	}
}
