package requirementgraph

import (
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestGraphKindVocabularyPreservesNativeAdmission(t *testing.T) {
	kinds := []string{"capability_spec", "meta_spec", "module_spec", "requirement", "submodule_spec"}
	if !slices.Equal(slices.Sorted(maps.Keys(specificationNodeKinds)), kinds) {
		t.Fatal("native specification kind set changed")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(codeLevels)), []string{"file", "module", "package", "repository", "source_range", "symbol"}) {
		t.Fatal("native code kind set changed")
	}
	for _, kind := range append(slices.Clone(kinds), "", "foreign", "repository", "source_range") {
		node := map[string]any{"evidencePlane": "specification_coverage", "nodeId": "spec:fixture", "sourceId": "fixture", "label": "Fixture", "kind": kind}
		if kind == "requirement" {
			node["nodeId"], node["label"] = "requirement:fixture", "fixture"
		}
		err := admitGraphNode(node)
		if (err == nil) != slices.Contains(kinds, kind) {
			t.Fatalf("native kind truth table changed for %q", kind)
		}
	}
}

func TestGraphOutputStructureIsDetached(t *testing.T) {
	before := OutputStructure()
	mutated := OutputStructure()
	mutated["properties"].(map[string]any)["nodes"].(map[string]any)["items"].(map[string]any)["oneOf"] = []any{}
	delete(mutated["properties"].(map[string]any), "edgeCount")
	if !reflect.DeepEqual(before, OutputStructure()) {
		t.Fatal("caller changed native graph structure")
	}
	if _, err := Build(graphPermutationInput(t)); err != nil {
		t.Fatal("structure mutation changed native graph behavior")
	}
}
