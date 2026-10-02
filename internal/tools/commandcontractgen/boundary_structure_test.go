package main

import (
	"bytes"
	"maps"
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

type boundaryStructureFamily struct {
	command       string
	input, output func() map[string]any
}

func boundaryStructureFamilies() []boundaryStructureFamily {
	return []boundaryStructureFamily{
		{"custom-rule-boundary", customruleboundary.InputStructure, customruleboundary.OutputStructure},
		{"document-lifecycle-boundary", documentlifecycle.InputStructure, documentlifecycle.OutputStructure},
		{"rendered-artifact-freshness", renderedartifactfreshness.InputStructure, renderedartifactfreshness.OutputStructure},
		{"adoption-checklist", adoptionchecklist.InputStructure, adoptionchecklist.OutputStructure},
		{"binding-partition", bindingpartition.InputStructure, bindingpartition.OutputStructure},
		{"completion-criteria", completioncriteria.InputStructure, completioncriteria.OutputStructure},
		{"package-runtime-dependency-admission", packageruntimedependency.InputStructure, packageruntimedependency.OutputStructure},
		{"proof-obligation-algebra", proofobligationalgebra.InputStructure, proofobligationalgebra.OutputStructure},
		{"text-policy", textpolicy.InputStructure, textpolicy.OutputStructure},
	}
}

func TestBoundaryNativeStructuresRejectRehashedNestedDrift(t *testing.T) {
	for _, family := range boundaryStructureFamilies() {
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

func TestBoundaryNativeStructuresAreDetached(t *testing.T) {
	for _, family := range boundaryStructureFamilies() {
		for direction, projection := range map[string]func() map[string]any{"input": family.input, "output": family.output} {
			t.Run(family.command+"/"+direction, func(t *testing.T) {
				value := projection()
				before, err := canonicalJSON(value)
				if err != nil {
					t.Fatal(err)
				}
				restore := mutateStructureContainers(value)
				defer restore()
				after, err := canonicalJSON(projection())
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("mutating a returned container changed the owner projection")
				}
			})
		}
	}
}

// Visit children before replacing parents so nested aliases are exercised too.
func mutateStructureContainers(value any) func() {
	var restores []func()
	var mutate func(any)
	mutate = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			previous := maps.Clone(value)
			for _, child := range previous {
				mutate(child)
			}
			clear(value)
			value["unexpected"] = true
			restores = append(restores, func() { clear(value); maps.Copy(value, previous) })
		case []any:
			previous := slices.Clone(value)
			for index, child := range previous {
				mutate(child)
				value[index] = nil
			}
			restores = append(restores, func() { copy(value, previous) })
		}
	}
	mutate(value)
	return func() {
		for index := len(restores) - 1; index >= 0; index-- {
			restores[index]()
		}
	}
}
