package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

func aggregateStructureFixture() nativeStructure {
	return nativeStructure{
		id: "proofkit.aggregate.input.v4.json-schema", direction: "input", aggregateVersion: "4",
		commands: []string{"aggregate"},
		variants: []nativeStructureVariant{
			{id: "01-numeric", when: "numeric header", schema: func() (map[string]any, error) {
				return map[string]any{
					"type": "object", "additionalProperties": false,
					"properties": map[string]any{
						"authority":     map[string]any{"type": "string", "const": "caller_owned"},
						"schemaVersion": map[string]any{"type": "integer", "const": json.Number("3")},
					},
					"required": []any{"authority", "schemaVersion"},
				}, nil
			}},
			{id: "02-named", when: "named header", schema: func() (map[string]any, error) {
				return map[string]any{
					"type": "object", "additionalProperties": false,
					"properties": map[string]any{
						"schema":    map[string]any{"type": "string", "const": "proofkit.wrapped.v1"},
						"inventory": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}, "required": []any{}},
					},
					"required": []any{"inventory", "schema"},
				}, nil
			}},
		},
	}
}

func TestAggregateStructureSeparatesContractIdentityFromWireHeaders(t *testing.T) {
	owner := aggregateStructureFixture()
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	version, err := owner.contractVersion(definition)
	if err != nil || version != "4" || owner.contractID("aggregate", version) != "proofkit.aggregate.input.v4" {
		t.Fatalf("aggregate identity: version=%s error=%v", version, err)
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if len(variants) != 2 {
		t.Fatalf("got %d variants", len(variants))
	}
	for i, fields := range [][]any{{"authority", "schemaVersion"}, {"inventory", "schema"}} {
		variant := variants[i].(map[string]any)
		original, err := owner.variants[i].schema()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(variant["schema"], original) || !reflect.DeepEqual(variant["allowedFields"], fields) ||
			!reflect.DeepEqual(variant["requiredFields"], fields) {
			t.Fatal("aggregate changed a payload or its exact root fields")
		}
	}
	if want := []any{
		"contractSchemaVersion=4 (aggregate; wire headers are defined per variant)",
		"structural JSON Schema definition proofkit.aggregate.input.v4.json-schema; canonicalization and semantic validity remain native admission obligations",
	}; !reflect.DeepEqual(owner.summary(version), want) {
		t.Fatalf("wrong aggregate summary: %v", owner.summary(version))
	}
	fields, err := owner.inputRootSummary(definition)
	if err != nil || !reflect.DeepEqual(fields, []string{
		`root fields (01-numeric): authority="caller_owned", schemaVersion=3`,
		`root fields (02-named): inventory{}, schema="proofkit.wrapped.v1"`,
	}) {
		t.Fatalf("wire navigation=%v error=%v", fields, err)
	}
}

func TestAggregateStructureRejectsAmbiguousVersionAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*nativeStructure){
		"missing-opt-in":    func(o *nativeStructure) { o.aggregateVersion = "" },
		"zero":              func(o *nativeStructure) { o.aggregateVersion = "0" },
		"negative":          func(o *nativeStructure) { o.aggregateVersion = "-1" },
		"decimal":           func(o *nativeStructure) { o.aggregateVersion = "1.0" },
		"exponent":          func(o *nativeStructure) { o.aggregateVersion = "1e0" },
		"overflow":          func(o *nativeStructure) { o.aggregateVersion = "9223372036854775808" },
		"one-variant":       func(o *nativeStructure) { o.variants = o.variants[:1] },
		"no-variants":       func(o *nativeStructure) { o.schema = o.variants[0].schema; o.variants = nil },
		"scalar-schema":     func(o *nativeStructure) { o.schema = o.variants[0].schema },
		"inline-selector":   func(o *nativeStructure) { o.wireVersion = "3" },
		"version-field":     func(o *nativeStructure) { o.versionField = "schemaVersion" },
		"out-of-band":       func(o *nativeStructure) { o.outOfBandVersion = "4" },
		"optional-inline":   func(o *nativeStructure) { o.optionalInputVersion = true },
		"semantic-override": func(o *nativeStructure) { o.semanticVersion = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			owner := aggregateStructureFixture()
			mutate(&owner)
			if _, err := owner.definition(); err == nil {
				t.Fatal("ambiguous aggregate was accepted")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"open":          func(s map[string]any) { s["additionalProperties"] = true },
		"wrong-type":    func(s map[string]any) { s["type"] = "array" },
		"no-properties": func(s map[string]any) { delete(s, "properties") },
	} {
		t.Run(name, func(t *testing.T) {
			owner := aggregateStructureFixture()
			schema, err := owner.variants[1].schema()
			if err != nil {
				t.Fatal(err)
			}
			mutate(schema)
			owner.variants[1].schema = func() (map[string]any, error) { return schema, nil }
			if _, err := owner.definition(); err == nil {
				t.Fatal("non-closed aggregate variant was accepted")
			}
		})
	}
}

func TestNativeDefinitionsMatchPublishedOwners(t *testing.T) {
	contract := readFixtureContract(t, filepath.Join("..", "..", ".."))
	definitions := map[string]map[string]any{}
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		definitions[definition["definitionId"].(string)] = definition
	}
	for _, owner := range nativeStructures() {
		expected, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		expectedBytes, err := canonicalJSON(expected)
		if err != nil {
			t.Fatal(err)
		}
		publishedBytes, err := canonicalJSON(definitions[owner.id])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expectedBytes, publishedBytes) {
			t.Fatalf("published definition differs from owner %s", owner.id)
		}
	}
}
