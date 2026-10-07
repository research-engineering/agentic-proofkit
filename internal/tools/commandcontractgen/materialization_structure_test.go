package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestAdoptionStructuresBindSevenDirectionsAndRetainIdentities(t *testing.T) {
	for _, row := range []struct {
		id, command, direction, wire, semantic string
		build                                  func() (map[string]any, error)
	}{
		{"proofkit.repository-inventory.output.v1.json-schema", "repository-inventory", "output", "1", "1", func() (map[string]any, error) { return repositoryinventory.OutputStructure(), nil }},
		{"proofkit.adopt-plan.output.v1.json-schema", "adopt-plan", "output", "1", "1", adoptionplan.OutputStructure},
		{"proofkit.adoption-materialization.plan-input.v2.json-schema", "adopt-materialize-plan", "input", "2", "3", adoptionmaterialization.InputStructure},
		{"proofkit.adoption-materialization.apply-input.v2.json-schema", "adopt-materialize-apply", "input", "2", "3", adoptionmaterialization.InputStructure},
		{"proofkit.adoption-materialization.plan-output.v1.json-schema", "adopt-materialize-plan", "output", "1", "2", func() (map[string]any, error) { return adoptionmaterialization.PlanOutputStructure(), nil }},
		{"proofkit.adoption-materialization.apply-output.v1.json-schema", "adopt-materialize-apply", "output", "1", "2", func() (map[string]any, error) { return adoptionmaterialization.ReceiptOutputStructure("apply") }},
		{"proofkit.adoption-materialization.recover-output.v1.json-schema", "adopt-materialize-recover", "output", "1", "2", func() (map[string]any, error) { return adoptionmaterialization.ReceiptOutputStructure("recover") }},
	} {
		owner, exists := nativeStructureOwner(row.id)
		if !exists || owner.direction != row.direction || !reflect.DeepEqual(owner.commands, []string{row.command}) {
			t.Fatalf("missing or wrong owner: %s", row.id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number(row.wire) || owner.contractID(row.command, version) != "proofkit."+row.command+"."+row.direction+".v"+row.semantic {
			t.Fatalf("wire/semantic identity drift: %s %s %v", row.id, version, err)
		}
		want, err := row.build()
		if err != nil {
			t.Fatal(err)
		}
		variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
		if !reflect.DeepEqual(variant["schema"], want) {
			t.Fatalf("schema is not child-owner-derived: %s", row.id)
		}
		for _, mutation := range []string{"open", "required", "version"} {
			changed, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			if choices, ok := schema["oneOf"].([]any); ok {
				schema = choices[1].(map[string]any)
			}
			switch mutation {
			case "open":
				schema["additionalProperties"] = true
			case "required":
				schema["required"] = []any{}
			case "version":
				schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("99")
			}
			delete(changed, "canonicalDigest")
			encoded, err := canonicalJSON(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed["canonicalDigest"] = sha256Digest(encoded)
			if admitNativeStructureDefinition(row.id, changed) == nil {
				t.Fatalf("accepted coherently rehashed %s/%s drift", row.id, mutation)
			}
		}
	}
	input, err := adoptionmaterialization.InputStructure()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adoptionplan.OutputStructure()
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range []struct {
		path []any
		want map[string]any
	}{
		{[]any{"sourcePlan"}, plan},
		{[]any{"requirementProofBinding", "record"}, requirementbinding.InputShape().JSONSchema()},
		{[]any{"testEvidenceInventory", "record"}, testevidenceinventory.DirectInputShape().JSONSchema()},
	} {
		got, err := schemaChildAtPath(input, child.path)
		if err != nil || !equalSchemaIgnoringDialect(got, child.want) {
			t.Fatalf("parent redefined child %v: %v", child.path, err)
		}
	}
	input["properties"].(map[string]any)["foreign"] = true
	other, err := adoptionmaterialization.InputStructure()
	if err != nil || reflect.DeepEqual(input, other) {
		t.Fatalf("returned mutable shared schema: %v", err)
	}
}

func TestStructureEnrichmentPreservesIndependentCompatibilityNotes(t *testing.T) {
	root := writeNativeStructureFixture(t)
	source, before, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	owner := nativeStructures()[0]
	for _, raw := range before["commands"].([]any) {
		command := raw.(map[string]any)
		if command["command"] != owner.commands[0] {
			continue
		}
		input := command["inputContract"].(map[string]any)
		input["compatibilitySummary"] = append(input["compatibilitySummary"].([]any), "Independent policy remains unchanged.", "Retained version note remains last.")
	}
	updated, err := refreshStructureSource(source, before)
	if err != nil {
		t.Fatal(err)
	}
	after, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
	if err != nil {
		t.Fatal(err)
	}
	input := commandAt(after.(map[string]any), owner.commands[0])["inputContract"].(map[string]any)
	want := append(owner.summary(json.Number("1")), "closed native admission contract", "Independent policy remains unchanged.", "Retained version note remains last.")
	if !reflect.DeepEqual(input["compatibilitySummary"], want) {
		t.Fatalf("independent compatibility notes changed: %v", input["compatibilitySummary"])
	}
	second, err := refreshStructureSource(updated, after.(map[string]any))
	if err != nil || !bytes.Equal(updated, second) {
		t.Fatalf("summary enrichment is not idempotent: %v", err)
	}
}
