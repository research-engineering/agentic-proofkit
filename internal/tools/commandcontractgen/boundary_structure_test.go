package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionchecklist"
	"github.com/research-engineering/agentic-proofkit/internal/command/bindingpartition"
	"github.com/research-engineering/agentic-proofkit/internal/command/completioncriteria"
	"github.com/research-engineering/agentic-proofkit/internal/command/customruleboundary"
	"github.com/research-engineering/agentic-proofkit/internal/command/documentlifecycle"
	"github.com/research-engineering/agentic-proofkit/internal/command/packageruntimedependency"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofobligationalgebra"
	"github.com/research-engineering/agentic-proofkit/internal/command/renderedartifactfreshness"
	"github.com/research-engineering/agentic-proofkit/internal/command/textpolicy"
)

func TestBoundaryNativeStructuresRejectRehashedNestedDrift(t *testing.T) {
	for _, family := range []struct {
		command       string
		input, output func() map[string]any
	}{
		{"custom-rule-boundary", customruleboundary.InputStructure, customruleboundary.OutputStructure},
		{"document-lifecycle-boundary", documentlifecycle.InputStructure, documentlifecycle.OutputStructure},
		{"rendered-artifact-freshness", renderedartifactfreshness.InputStructure, renderedartifactfreshness.OutputStructure},
		{"adoption-checklist", adoptionchecklist.InputStructure, adoptionchecklist.OutputStructure},
		{"binding-partition", bindingpartition.InputStructure, bindingpartition.OutputStructure},
		{"completion-criteria", completioncriteria.InputStructure, completioncriteria.OutputStructure},
		{"package-runtime-dependency-admission", packageruntimedependency.InputStructure, packageruntimedependency.OutputStructure},
		{"proof-obligation-algebra", proofobligationalgebra.InputStructure, proofobligationalgebra.OutputStructure},
		{"text-policy", textpolicy.InputStructure, textpolicy.OutputStructure},
	} {
		for _, direction := range []string{"input", "output"} {
			id := "proofkit." + family.command + "." + direction + ".v1.json-schema"
			t.Run(id, func(t *testing.T) {
				index := slices.IndexFunc(nativeStructures(), func(owner nativeStructure) bool { return owner.id == id })
				if index < 0 {
					t.Fatalf("missing owner %s", id)
				}
				owner := nativeStructures()[index]
				if owner.direction != direction || !slices.Equal(owner.commands, []string{family.command}) || !slices.Equal(owner.predecessors, []string{"proofkit." + family.command + "." + direction + ".v1.root-shape"}) {
					t.Fatal("wrong exact native consumer binding")
				}
				projection := family.input
				if direction == "output" {
					projection = family.output
				}
				row, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				variant := row["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				expected := projection()
				if !reflect.DeepEqual(variant["schema"], expected) {
					t.Fatal("schema differs from its native owner")
				}
				if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{row}}); err != nil {
					t.Fatal(err)
				}
				variant["schema"].(map[string]any)["properties"].(map[string]any)["nonClaims"].(map[string]any)["items"] = map[string]any{"type": "boolean"}
				if !reflect.DeepEqual(projection(), expected) {
					t.Fatal("caller mutation changed the authoritative projection")
				}
				delete(row, "canonicalDigest")
				encoded, err := canonicalJSON(row)
				if err != nil {
					t.Fatal(err)
				}
				row["canonicalDigest"] = sha256Digest(encoded)
				if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{row}}); err == nil {
					t.Fatal("a recomputed digest authorized nested schema drift")
				}
			})
		}
	}
}
