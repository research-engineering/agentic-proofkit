package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishedContractReferenceInventoryAcceptsCurrentNativeSchema(t *testing.T) {
	contract := mustReadBytes(t, filepath.Join("..", "..", "..", "proofkit", "cli-contract.v2.json"))
	entries := map[string]struct{}{"package/proofkit/command-families.v1.json": {}}
	if err := verifyCLIContractSourceClassifications(string(contract), entries); err != nil {
		t.Fatalf("actual public contract cannot pass package reference classification: %v", err)
	}
}

func TestSchemaPropertyNamesAreNotPackageReferences(t *testing.T) {
	for _, schema := range []map[string]any{
		{"properties": map[string]any{"witnessPath": map[string]any{"type": "string"}, "$ref": true, "sourceRef": false}},
		{"properties": map[string]any{"records": map[string]any{"items": map[string]any{"properties": map[string]any{"witnessSelectors": map[string]any{"type": "array"}}}}}},
		{"anyOf": []any{map[string]any{"properties": map[string]any{"sourcePath": map[string]any{"type": "string"}}}, map[string]any{"type": "null"}}},
		{"prefixItems": []any{map[string]any{"properties": map[string]any{"ref": map[string]any{"type": "string"}}}}},
	} {
		if err := checkSchemaReferenceFixture(t, schema, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSchemaReferenceInventoryCannotHideRealReferences(t *testing.T) {
	tests := []struct {
		name   string
		schema map[string]any
		mutate func(map[string]any)
		want   string
	}{
		{"schema-ref", map[string]any{"$ref": "missing.json"}, nil, "unclassified reference-bearing field"},
		{"property-schema-ref", map[string]any{"properties": map[string]any{"safe": map[string]any{"$ref": "missing.json"}}}, nil, "unclassified reference-bearing field"},
		{"prefix-item-schema-ref", map[string]any{"prefixItems": []any{map[string]any{"$ref": "missing.json"}}}, nil, "unclassified reference-bearing field"},
		{"metadata-path", map[string]any{"properties": map[string]any{"safe": map[string]any{"documentationPath": "missing.md"}}}, nil, "unclassified reference-bearing field"},
		{"malformed-properties", map[string]any{"properties": []any{}}, nil, "properties must be an object"},
		{"instance-in-properties", map[string]any{"properties": map[string]any{"sourcePath": "missing.json"}}, nil, "property declaration must be"},
		{"wrong-kind", propertySchemaFixture(), func(contract map[string]any) { schemaFieldTree(contract)["kind"] = "root_shape_only" }, "unclassified reference-bearing field"},
		{"missing-kind", propertySchemaFixture(), func(contract map[string]any) { delete(schemaFieldTree(contract), "kind") }, "unclassified reference-bearing field"},
		{"outside-definition", propertySchemaFixture(), func(contract map[string]any) {
			contract["unrelated"] = contract["contractDefinitions"]
			delete(contract, "contractDefinitions")
		}, "unclassified reference-bearing field"},
		{"outside-schema", map[string]any{"type": "object"}, func(contract map[string]any) {
			schemaFieldTree(contract)["properties"] = map[string]any{"sourcePath": "missing.json"}
		}, "unclassified reference-bearing field"},
		{"metadata-lookalike", map[string]any{"metadata": map[string]any{"properties": map[string]any{"sourcePath": "missing.json"}}}, nil, "unclassified reference-bearing field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkSchemaReferenceFixture(t, test.schema, test.mutate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wrong reference result: %v, want %q", err, test.want)
			}
		})
	}
}

func propertySchemaFixture() map[string]any {
	return map[string]any{"properties": map[string]any{"sourcePath": map[string]any{"type": "string"}}}
}

func schemaFieldTree(contract map[string]any) map[string]any {
	return contract["contractDefinitions"].([]any)[0].(map[string]any)["fieldTree"].(map[string]any)
}

func checkSchemaReferenceFixture(t *testing.T, schema map[string]any, mutate func(map[string]any)) error {
	t.Helper()
	contract := map[string]any{
		"commands": []any{},
		"contractDefinitions": []any{map[string]any{
			"fieldTree": map[string]any{"kind": "structural_json_schema", "variants": []any{map[string]any{"schema": schema}}},
		}},
	}
	if mutate != nil {
		mutate(contract)
	}
	data, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	return verifyCLIContractSourceClassifications(string(data), nil)
}
