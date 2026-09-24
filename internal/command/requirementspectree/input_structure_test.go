package requirementspectree

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestTreeInputStructurePreservesAllReferenceForms(t *testing.T) {
	input := validTreeInput()
	result, err := Evaluate(input)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("fixture: %v", err)
	}
	value := TreeValue(result.Tree)
	again, err := Evaluate(value)
	if err != nil || again.ExitCode != 0 || !reflect.DeepEqual(again.Tree, result.Tree) {
		t.Fatalf("tree value is not a closed owner projection: %v", err)
	}
	owned, err := InputShape().Admit(input, "tree")
	if err != nil {
		t.Fatal(err)
	}
	nodeMap(input, "meta")["label"] = "changed"
	if nodeMap(owned.(map[string]any), "meta")["label"] != "Meta specification" {
		t.Fatal("tree structural admission retained an alias")
	}
	for _, kind := range []string{"source_id", "path_digest"} {
		for _, forbidden := range map[string][]string{"source_id": {"sourcePath", "currentSourceDigest", "recordedSourceDigest", "digestAlgorithm"}, "path_digest": {"sourceId"}}[kind] {
			for _, value := range []any{nil, "surplus"} {
				v := validTreeInput()
				node, ref := "meta", "source.meta"
				if kind == "path_digest" {
					node, ref = "submodule", "source.submodule"
				}
				sourceRefMap(v, node, ref)[forbidden] = value
				if _, err := InputShape().Admit(v, "tree"); err == nil {
					t.Fatal("forbidden variant field admitted, including present null")
				}
			}
		}
	}
	for _, key := range []string{"refPath", "refDigest", "digestAlgorithm"} {
		v := validTreeInput()
		delete(overlayMap(v, "overlay.rendered.module"), key)
		if _, err := InputShape().Admit(v, "tree"); err == nil {
			t.Fatal("partial overlay path/digest group admitted")
		}
	}
	for _, version := range []any{json.Number("2.0"), json.Number("2e0"), 2} {
		v := validTreeInput()
		v["schemaVersion"] = version
		if _, err := Evaluate(v); err == nil {
			t.Fatal("noncanonical version admitted")
		}
	}
}

func TestTreeInputStructureBudgetBoundariesAreIsolated(t *testing.T) {
	for _, tc := range []struct {
		key   string
		limit int
	}{{"nodes", 4096}, {"edges", 8192}, {"overlays", 4096}} {
		for _, count := range []int{tc.limit, tc.limit + 1} {
			v := validTreeInput()
			validElement := v[tc.key].([]any)[0]
			items := make([]any, count)
			for i := range items {
				items[i] = validElement
			}
			v[tc.key] = items
			_, err := InputShape().Admit(v, "tree")
			if count == tc.limit && err != nil {
				t.Fatalf("exact %s structural budget rejected: %v", tc.key, err)
			}
			if count > tc.limit && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf(".%s must contain at most %d items", tc.key, tc.limit))) {
				t.Fatalf("missing %s budget guard: %v", tc.key, err)
			}
		}
	}
}
