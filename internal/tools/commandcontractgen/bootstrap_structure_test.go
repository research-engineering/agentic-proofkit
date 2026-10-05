package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/selfcheck"
)

func TestBootstrapJSONValueModeHasExactHeaderAndVersionSemantics(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.self-check.input.v1.json-schema")
	if !ok {
		t.Fatal("missing bootstrap input owner")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if definition["rootType"] != "json_value" || variant["rootKind"] != "json_value" ||
		!reflect.DeepEqual(variant["allowedFields"], []any{}) || !reflect.DeepEqual(variant["requiredFields"], []any{}) ||
		!reflect.DeepEqual(variant["schema"], selfcheck.InputStructure()) {
		t.Fatal("arbitrary JSON input became a field-constrained root")
	}
	if version, err := owner.contractVersion(definition); err != nil || version != "1" {
		t.Fatalf("version=%s error=%v", version, err)
	}
	if summary, err := owner.inputRootSummary(definition); err != nil || !reflect.DeepEqual(summary, []string{"any JSON value; no required fields or inline version header"}) {
		t.Fatalf("summary=%v error=%v", summary, err)
	}
	if owner.summary("1")[0] != "contractSchemaVersion=1 (out-of-band; arbitrary input members are not version headers)" {
		t.Fatal("input navigation mistakes an arbitrary member for a version header")
	}
	if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name   string
		mutate func(*nativeStructure)
	}{
		{"output", func(x *nativeStructure) { x.direction = "output" }},
		{"missing-version", func(x *nativeStructure) { x.outOfBandVersion = "" }},
		{"zero-version", func(x *nativeStructure) { x.outOfBandVersion = "0" }},
		{"noncanonical-version", func(x *nativeStructure) { x.outOfBandVersion = json.Number("1.0") }},
		{"inline-version", func(x *nativeStructure) { x.wireVersion = "1" }},
		{"version-field", func(x *nativeStructure) { x.versionField = "version" }},
		{"optional-version", func(x *nativeStructure) { x.optionalInputVersion = true }},
		{"aggregate-version", func(x *nativeStructure) { x.aggregateVersion = "1" }},
		{"semantic-version", func(x *nativeStructure) { x.semanticVersion = 1 }},
		{"variants", func(x *nativeStructure) {
			x.variants = []nativeStructureVariant{{id: "01-value", when: "default", schema: x.schema}}
		}},
		{"constrained", func(x *nativeStructure) {
			x.schema = func() (map[string]any, error) {
				value := selfcheck.InputStructure()
				value["type"] = "object"
				return value, nil
			}
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			bad := owner
			item.mutate(&bad)
			if _, err := bad.definition(); err == nil {
				t.Fatal("conflicting arbitrary-input mode was accepted")
			}
		})
	}
}

func TestBootstrapOutputOwnerDoesNotReuseArbitraryInputMode(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.self-check.output.v1.json-schema")
	if !ok || owner.jsonValueInput || owner.outOfBandVersion != "" {
		t.Fatal("bootstrap output has no ordinary inline-version owner")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if definition["rootType"] != "object" || variant["rootKind"] != "object" || !reflect.DeepEqual(variant["schema"], selfcheck.OutputStructure()) {
		t.Fatal("bootstrap output owner drift")
	}
	if version, err := owner.contractVersion(definition); err != nil || version != "1" {
		t.Fatalf("version=%s error=%v", version, err)
	}
	if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapJSONValueAnnotationsRemainNonSemantic(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.self-check.input.v1.json-schema")
	if !ok {
		t.Fatal("missing bootstrap owner")
	}
	withoutDescription := owner
	withoutDescription.schema = func() (map[string]any, error) {
		return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema"}, nil
	}
	definition, err := withoutDescription.definition()
	if err != nil {
		t.Fatalf("optional description was required: %v", err)
	}
	if version, err := withoutDescription.contractVersion(definition); err != nil || version != "1" {
		t.Fatalf("annotation-free version=%s error=%v", version, err)
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(variant["schema"], map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema"}) {
		t.Fatal("optional annotation changed the accepted value domain")
	}
	for _, description := range []any{nil, false, json.Number("1"), "", " \t ", []any{}, map[string]any{}} {
		bad := owner
		bad.schema = func() (map[string]any, error) {
			value := selfcheck.InputStructure()
			value["description"] = description
			return value, nil
		}
		if _, err := bad.definition(); err == nil {
			t.Fatalf("invalid present description accepted: %T", description)
		}
	}
	for _, schema := range []map[string]any{{}, {"$schema": nil}, {"$schema": "foreign"},
		{"$schema": "https://json-schema.org/draft/2020-12/schema", "properties": map[string]any{}},
	} {
		bad := owner
		bad.schema = func() (map[string]any, error) { return schema, nil }
		if _, err := bad.definition(); err == nil {
			t.Fatal("missing dialect or constraint keyword accepted")
		}
	}
}
