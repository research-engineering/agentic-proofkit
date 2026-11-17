package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeConsumerIdentityReceiptRenderBoundary(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"receipt-producer-admission", "obligation-decision"} {
		for _, mutation := range []string{"unchanged", "id-only", "version-only", "both"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				_, contract, err := readContractInput(bytes.NewReader(source))
				if err != nil {
					t.Fatal(err)
				}
				binding := commandAt(contract, name)["inputContract"].(map[string]any)
				if binding["contractId"] != "proofkit."+name+".input.v1" || binding["schemaVersion"] != json.Number("1") {
					t.Fatal("baseline input identity is not independently fixed v1")
				}
				definitions, err := admitDefinitions(contract)
				if err != nil {
					t.Fatal(err)
				}
				definition := definitions[binding["rootDefinitionRef"].(string)].Content
				variants, err := expandedVariants(definition)
				if err != nil {
					t.Fatal(err)
				}
				for _, raw := range variants {
					schema := raw.(map[string]any)["schema"].(map[string]any)
					version, err := nativeSchemaVersion(schema, "schemaVersion")
					if err != nil || version != json.Number("1") {
						t.Fatalf("native input header changed: %s %v", version, err)
					}
				}
				if mutation == "id-only" || mutation == "both" {
					binding["contractId"] = "proofkit." + name + ".input.v9"
				}
				if mutation == "version-only" || mutation == "both" {
					binding["schemaVersion"] = json.Number("9")
				}
				encoded := source
				if mutation != "unchanged" {
					encoded, err = json.Marshal(contract)
					if err != nil {
						t.Fatal(err)
					}
				}
				serialized, admitted, err := readContractInput(bytes.NewReader(encoded))
				if err != nil {
					t.Fatalf("serialized candidate did not reach render admission: %v", err)
				}
				app, presets, err := renderContract(root, serialized, admitted)
				if mutation == "unchanged" {
					if err != nil || len(app) == 0 || len(presets) == 0 {
						t.Fatalf("unchanged production contract failed to render: %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "native semantic contract identity") {
					t.Fatalf("identity drift reached projection or wrong rejection: %v", err)
				}
				if app != nil || presets != nil {
					t.Fatal("rejected identity produced a projection")
				}
			})
		}
	}
}

func TestNativeConsumerIdentityAllOwners(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := admitNativeStructureConsumers(contract, definitions); err != nil {
		t.Fatalf("unchanged production consumers: %v", err)
	}
	for _, owner := range nativeStructures() {
		for _, name := range owner.commands {
			binding := commandAt(contract, name)[owner.direction+"Contract"].(map[string]any)
			originalID, originalVersion := binding["contractId"], binding["schemaVersion"]
			for _, mutation := range []string{"id-only", "version-only", "both"} {
				t.Run(name+"/"+owner.direction+"/"+mutation, func(t *testing.T) {
					defer func() { binding["contractId"], binding["schemaVersion"] = originalID, originalVersion }()
					if mutation == "id-only" || mutation == "both" {
						binding["contractId"] = "proofkit." + name + "." + owner.direction + ".v999"
					}
					if mutation == "version-only" || mutation == "both" {
						binding["schemaVersion"] = json.Number("999")
					}
					if err := admitNativeStructureConsumers(contract, definitions); err == nil || !strings.Contains(err.Error(), "contract identity") {
						t.Fatalf("native consumer admitted %s or failed for unrelated cause: %v", mutation, err)
					}
				})
			}
		}
	}
}

func TestNativeConsumerIdentityRequiresOwnerContent(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	owner := nativeStructures()[0]
	definitions[owner.id] = definitionRecord{ID: owner.id}
	if err := admitNativeStructureConsumers(contract, definitions); err == nil || !strings.Contains(err.Error(), "lacks its native structural owner") {
		t.Fatalf("incomplete structural owner did not give a normal admission error: %v", err)
	}
}

func TestNativeConsumerIdentityProtectedVersionOwners(t *testing.T) {
	for _, row := range []struct {
		ownerID, command, direction, semantic, wire string
	}{
		{"proofkit.requirement-bindings.input.v1.json-schema", "evidence-graph", "input", "1", "1"},
		{"proofkit.requirement-bindings.input.v1.json-schema", "proof-slice", "input", "1", "1"},
		{"proofkit.requirement-bindings.input.v1.json-schema", "requirement-bindings", "input", "1", "1"},
		{"proofkit.requirement-source.input.v2.json-schema", "requirement-source-admission", "input", "2", "2"},
		{"proofkit.requirement-source.input.v2.json-schema", "requirement-source-view", "input", "2", "2"},
		{"proofkit.adoption-materialization.plan-input.v2.json-schema", "adopt-materialize-plan", "input", "3", "2"},
		{"proofkit.integration-plan.output.v1.json-schema", "integration-plan", "output", "2", "1"},
		{"proofkit.witness-plan.input.v1.json-schema", "witness-plan", "input", "1", "1"},
		{"proofkit.witness-plan.output.v1.json-schema", "witness-plan", "output", "1", "1"},
		{"proofkit.requirement-source-conversion.output.v1.json-schema", "requirement-source-conversion", "output", "1", "1"},
		{"proofkit.test-evidence-inventory.input.v3.json-schema", "test-evidence-inventory", "input", "3", "3"},
		{"proofkit.adoption-contract-envelope.output.v2.json-schema", "adoption-contract-envelope", "output", "2", "1"},
	} {
		t.Run(row.command+"/"+row.direction, func(t *testing.T) {
			owner, ok := nativeStructureOwner(row.ownerID)
			if !ok {
				t.Fatal("protected native owner missing")
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			version, err := owner.contractVersion(definition)
			wantID := fmt.Sprintf("proofkit.%s.%s.v%s", row.command, row.direction, row.semantic)
			if err != nil || version != json.Number(row.wire) || owner.contractID(row.command, version) != wantID {
				t.Fatalf("protected semantic/wire identity changed: %s %v", version, err)
			}
		})
	}
}
