package requirementcontext

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCatalogStructurePreservesNullableDefaultsAndRoles(t *testing.T) {
	minimal := fixtureCatalog()
	_, expected, err := admitCatalog(minimal)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"coverage", "proofBinding"} {
		raw := fixtureCatalog()
		raw[key] = nil
		entry := raw["specTree"].(map[string]any)
		entry["nodeId"], entry["sourceRef"], entry["expectedSourceDigest"] = nil, nil, nil
		id, entries, err := admitCatalog(raw)
		if err != nil || id != "consumer.spec-context" || !reflect.DeepEqual(entries, expected) {
			t.Fatalf("null/default semantics drift: %v %#v", err, entries)
		}
		raw[key] = map[string]any{"path": "proofkit/" + key + ".json", "nodeId": nil}
		_, entries, err = admitCatalog(raw)
		if err != nil || len(entries) != 3 {
			t.Fatalf("optional entry rejected: %v", err)
		}
	}
	for _, suffix := range []string{"", " ", "  "} {
		raw := fixtureCatalog()
		path := "proofkit/spec-tree.json" + suffix
		raw["specTree"].(map[string]any)["path"] = path
		_, entries, err := admitCatalog(raw)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.Kind == "spec_tree" {
				found = entry.Path == path
			}
		}
		if !found {
			t.Fatal("catalog rewrote a distinct POSIX path")
		}
	}
	owned, err := catalogInputShape.Admit(minimal, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	minimal["specTree"].(map[string]any)["path"] = "changed.json"
	if owned.(map[string]any)["specTree"].(map[string]any)["path"] != "proofkit/spec-tree.json" {
		t.Fatal("structural catalog retained caller aliases")
	}
}

func TestCatalogStructureRejectsRoleAndFieldDrift(t *testing.T) {
	for key := range fixtureCatalog() {
		for _, mode := range []string{"missing", "null", "wrong type"} {
			raw := fixtureCatalog()
			if mode == "missing" {
				delete(raw, key)
			} else if mode == "null" {
				raw[key] = nil
			} else {
				raw[key] = false
			}
			if _, _, err := admitCatalog(raw); err == nil {
				t.Fatalf("%s %s admitted", mode, key)
			}
		}
	}
	for name, change := range map[string]func(map[string]any){
		"unknown root":             func(v map[string]any) { v["extra"] = true },
		"unknown entry":            func(v map[string]any) { v["specTree"].(map[string]any)["extra"] = true },
		"missing path":             func(v map[string]any) { delete(v["specTree"].(map[string]any), "path") },
		"null path":                func(v map[string]any) { v["specTree"].(map[string]any)["path"] = nil },
		"wrong digest":             func(v map[string]any) { v["specTree"].(map[string]any)["expectedSourceDigest"] = true },
		"wrong ref":                func(v map[string]any) { v["specTree"].(map[string]any)["sourceRef"] = []any{} },
		"nonrequirement node":      func(v map[string]any) { v["specTree"].(map[string]any)["nodeId"] = "spec.root" },
		"missing requirement node": func(v map[string]any) { delete(v["requirementSources"].([]any)[0].(map[string]any), "nodeId") },
		"null requirement node":    func(v map[string]any) { v["requirementSources"].([]any)[0].(map[string]any)["nodeId"] = nil },
		"empty sources":            func(v map[string]any) { v["requirementSources"] = []any{} },
		"wrong optional record":    func(v map[string]any) { v["coverage"] = []any{} },
		"wrong version":            func(v map[string]any) { v["schemaVersion"] = json.Number("1") },
		"noncanonical version":     func(v map[string]any) { v["schemaVersion"] = json.Number("2.0") },
	} {
		t.Run(name, func(t *testing.T) {
			raw := fixtureCatalog()
			change(raw)
			if _, _, err := admitCatalog(raw); err == nil {
				t.Fatal("invalid catalog admitted")
			}
		})
	}
}
