package main

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/publicapi"
)

func TestPublicAPIStructuresRejectRehashedDrift(t *testing.T) {
	for direction, projection := range map[string]func() map[string]any{
		"input": publicapi.InputStructure, "output": publicapi.OutputStructure,
	} {
		t.Run(direction, func(t *testing.T) {
			id := "proofkit.typescript-public-api-surfaces." + direction + ".v1.json-schema"
			owner, ok := nativeStructureOwner(id)
			if !ok || owner.direction != direction || !slices.Equal(owner.commands, []string{"typescript-public-api-surfaces"}) || !slices.Equal(owner.predecessors, []string{"proofkit.typescript-public-api-surfaces." + direction + ".v1.root-shape"}) {
				t.Fatal("missing exact public API structure owner")
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
			expected := projection()
			if !reflect.DeepEqual(variant["schema"], expected) {
				t.Fatal("registered projection differs from native owner")
			}
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
				t.Fatal(err)
			}
			restore := mutateStructureContainers(variant["schema"])
			if !reflect.DeepEqual(projection(), expected) {
				t.Fatal("returned schema mutation changed the owner")
			}
			restore()
			variant["schema"].(map[string]any)["additionalProperties"] = true
			delete(definition, "canonicalDigest")
			encoded, err := canonicalJSON(definition)
			if err != nil {
				t.Fatal(err)
			}
			definition["canonicalDigest"] = sha256Digest(encoded)
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err == nil {
				t.Fatal("rehashing authorized unowned schema drift")
			}
		})
	}
}

func TestOutOfBandContractVersionDoesNotInventWireFields(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.typescript-public-api-surfaces.output.v1.json-schema")
	if !ok {
		t.Fatal("missing public API output owner")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	version, err := owner.contractVersion(definition)
	if err != nil || version != "1" {
		t.Fatalf("contract version=%q error=%v", version, err)
	}
	if !strings.Contains(owner.summary(version)[0].(string), "out-of-band; no serialized schemaVersion field") {
		t.Fatal("summary confuses contract version with a wire field")
	}
	for _, test := range []struct {
		name   string
		mutate func(*nativeStructure, map[string]any)
	}{
		{"missing-opt-in", func(owner *nativeStructure, _ map[string]any) { owner.outOfBandVersion = "" }},
		{"zero", func(owner *nativeStructure, _ map[string]any) { owner.outOfBandVersion = "0" }},
		{"negative", func(owner *nativeStructure, _ map[string]any) { owner.outOfBandVersion = "-1" }},
		{"noncanonical", func(owner *nativeStructure, _ map[string]any) { owner.outOfBandVersion = "1.0" }},
		{"custom-inline-field", func(owner *nativeStructure, _ map[string]any) { owner.versionField = "version" }},
		{"inline-selector", func(owner *nativeStructure, _ map[string]any) { owner.wireVersion = "1" }},
		{"variants", func(owner *nativeStructure, _ map[string]any) {
			owner.variants = []nativeStructureVariant{{id: "01-valid", when: "default JSON mode", schema: owner.schema}}
		}},
		{"wire-field", func(_ *nativeStructure, schema map[string]any) {
			schema["properties"].(map[string]any)["schemaVersion"] = map[string]any{"type": "integer", "const": json.Number("1")}
		}},
		{"open-root", func(_ *nativeStructure, schema map[string]any) { schema["additionalProperties"] = true }},
		{"wrong-root", func(_ *nativeStructure, schema map[string]any) { schema["type"] = "array" }},
		{"missing-properties", func(_ *nativeStructure, schema map[string]any) { delete(schema, "properties") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := owner
			schema := publicapi.OutputStructure()
			test.mutate(&candidate, schema)
			candidate.schema = func() (map[string]any, error) { return schema, nil }
			if _, err := candidate.definition(); err == nil {
				t.Fatal("invalid version authority admitted")
			}
		})
	}
}
