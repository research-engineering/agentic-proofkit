package main

import (
	"reflect"
	"testing"
)

func TestGeneratedStarterOutputOwnersPreserveNoInputAndRootFields(t *testing.T) {
	for _, item := range []struct {
		command string
		fields  []any
	}{
		{"stack-preset", []any{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}},
		{"json-report-cli-adapter-source", []any{"artifactKind", "exportedSymbols", "format", "generatorId", "language", "nonClaims", "schemaVersion", "source", "sourceFileName", "sourceSha256", "summary"}},
	} {
		t.Run(item.command, func(t *testing.T) {
			owner, ok := nativeStructureOwner("proofkit." + item.command + ".output.v1.json-schema")
			if !ok || owner.direction != "output" || owner.jsonValueInput || owner.outOfBandVersion != "" {
				t.Fatal("missing ordinary inline-version output owner")
			}
			if _, ok := nativeStructureOwner("proofkit." + item.command + ".input.v1.json-schema"); ok {
				t.Fatal("no-input command gained a synthetic input record")
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
			if definition["rootType"] != "object" || variant["rootKind"] != "object" ||
				!reflect.DeepEqual(variant["allowedFields"], item.fields) || !reflect.DeepEqual(variant["requiredFields"], item.fields) {
				t.Fatal("output root field inventory drift")
			}
			if version, err := owner.contractVersion(definition); err != nil || version != "1" {
				t.Fatalf("version=%s error=%v", version, err)
			}
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
