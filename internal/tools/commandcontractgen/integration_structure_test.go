package main

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func TestIntegrationStructuresBindFiveOutputDirections(t *testing.T) {
	for _, row := range []struct {
		command, semantic string
		build             func() map[string]any
	}{
		{"integration-source", "1", agentintegration.SourceOutputStructure},
		{"integration-check", "1", agentintegration.CheckOutputStructure},
		{"integration-plan", "2", agentintegration.PlanOutputStructure},
		{"integration-apply", "2", agentintegration.ApplyOutputStructure},
		{"integration-recover", "2", agentintegration.RecoverOutputStructure},
	} {
		id := "proofkit." + row.command + ".output.v1.json-schema"
		owner, ok := nativeStructureOwner(id)
		if !ok || owner.direction != "output" || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{"proofkit." + row.command + ".output.v1.root-shape"}) {
			t.Fatalf("wrong native owner: %s", id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number("1") || owner.contractID(row.command, version) != "proofkit."+row.command+".output.v"+row.semantic {
			t.Fatalf("wire or semantic identity drift: %s %s %v", id, version, err)
		}
		schema := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"]
		if !reflect.DeepEqual(schema, row.build()) {
			t.Fatalf("schema not command-owner-derived: %s", id)
		}
		for _, mutation := range []string{"open", "required", "version"} {
			changed, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			if branches, ok := schema["oneOf"].([]any); ok {
				schema = branches[0].(map[string]any)
			}
			switch mutation {
			case "open":
				schema["additionalProperties"] = true
			case "required":
				schema["required"] = []any{}
			case "version":
				schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("2")
			}
			delete(changed, "canonicalDigest")
			encoded, err := canonicalJSON(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed["canonicalDigest"] = sha256Digest(encoded)
			if admitNativeStructureDefinition(id, changed) == nil {
				t.Fatalf("accepted coherently rehashed %s/%s drift", id, mutation)
			}
		}
	}
}

func TestIntegrationTransactionDescriptionsReuseChildOwnersAndDetach(t *testing.T) {
	for _, row := range []struct {
		build func() map[string]any
		field string
		child jsonshape.Shape
	}{
		{agentintegration.PlanOutputStructure, "transaction", repositorytransaction.PlanShape()},
		{agentintegration.ApplyOutputStructure, "transactionResult", repositorytransaction.ResultShape()},
		{agentintegration.RecoverOutputStructure, "transactionResult", repositorytransaction.ResultShape()},
	} {
		schema := row.build()
		child := schema["properties"].(map[string]any)[row.field].(map[string]any)
		if !equalSchemaIgnoringDialect(child, jsonshape.Nullable(row.child).JSONSchema()) {
			t.Fatalf("parent redefined transaction child %s", row.field)
		}
		child["foreign"] = true
		if reflect.DeepEqual(schema, row.build()) {
			t.Fatal("schema shares mutable child records")
		}
	}
}

func TestIntegrationEnrichmentClassifiesWholeOwnedAnnotationsOnly(t *testing.T) {
	for _, command := range []string{"integration-source", "integration-check", "integration-plan", "integration-apply", "integration-recover"} {
		owner, ok := nativeStructureOwner("proofkit." + command + ".output.v1.json-schema")
		if !ok {
			t.Fatal("integration output owner absent")
		}
		suffix := "nested field shapes, leaf types and relational semantics remain native-owner claims"
		if command == "integration-source" || command == "integration-check" {
			suffix = "nested fields, leaf types, cardinalities, and semantic validity remain native-owner claims"
		}
		annotation := "root-shape-only definition " + owner.predecessors[0] + "; " + suffix
		policy := "Preserve this independent caller policy."
		got, err := enrichedCompatibilitySummary(owner, "1", []any{"schemaVersion=1", annotation, policy})
		want := append(owner.summary("1"), policy)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("whole owned annotation or independent policy lost: %s %v", command, err)
		}
		for _, changed := range []string{annotation + " " + policy, annotation + "; " + policy, annotation + "\n" + policy} {
			if _, err := enrichedCompatibilitySummary(owner, "1", []any{"schemaVersion=1", changed}); err == nil {
				t.Fatalf("accepted ambiguous owned/policy text: %s", command)
			}
		}
	}
}
