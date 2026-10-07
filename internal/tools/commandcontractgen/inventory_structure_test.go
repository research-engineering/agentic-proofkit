package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
)

func TestInventoryAggregatesOwnExactModesAndClassifications(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	command := commandAt(contract, "test-evidence-inventory")
	for _, row := range []struct {
		direction, version string
		variants           []string
	}{
		{"input", "3", []string{"01-direct-inventory", "02-discovery-draft", "03-proof-binding-derived", "04-source-set", "05-wrapped-inventory"}},
		{"output", "2", []string{"01-normalized-direct", "02-normalized-proof-binding", "03-report", "04-discovery-report"}},
	} {
		owner, ok := nativeStructureOwner("proofkit.test-evidence-inventory." + row.direction + ".v" + row.version + ".json-schema")
		if !ok || owner.aggregateVersion != json.Number(row.version) {
			t.Fatal("inventory aggregate owner is missing")
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		actual := make([]string, len(variants))
		for i, variant := range variants {
			actual[i] = variant.(map[string]any)["variantId"].(string)
		}
		if !reflect.DeepEqual(actual, row.variants) {
			t.Fatalf("%s variants=%v want %v", row.direction, actual, row.variants)
		}
		binding := command[row.direction+"Contract"].(map[string]any)
		if binding["schemaVersion"] != json.Number(row.version) ||
			!reflect.DeepEqual(binding["compatibilitySummary"], owner.summary(json.Number(row.version))) {
			t.Fatal("aggregate metadata claims a uniform payload version")
		}
	}
	classes := []any{}
	for _, id := range testevidenceinventory.ClassificationIDs() {
		classes = append(classes, id)
	}
	if !reflect.DeepEqual(command["outputContract"].(map[string]any)["classificationIds"], classes) {
		t.Fatal("public classification vocabulary differs from native output owner")
	}
}

func TestInventoryAggregateConsumerIdentityRejectsIndependentMetadataDrift(t *testing.T) {
	for _, direction := range []string{"input", "output"} {
		for _, field := range []string{"schemaVersion", "contractId"} {
			t.Run(direction+"/"+field, func(t *testing.T) {
				_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
				if err != nil {
					t.Fatal(err)
				}
				definitions, err := admitDefinitions(contract)
				if err != nil {
					t.Fatal(err)
				}
				if err := admitNativeStructureConsumers(contract, definitions); err != nil {
					t.Fatalf("positive consumer control: %v", err)
				}
				binding := commandAt(contract, "test-evidence-inventory")[direction+"Contract"].(map[string]any)
				binding[field] = json.Number("1")
				if field == "contractId" {
					binding[field] = "proofkit.test-evidence-inventory." + direction + ".v1"
				}
				if err := admitNativeStructureConsumers(contract, definitions); err == nil || !strings.Contains(err.Error(), "native semantic contract identity") {
					t.Fatalf("aggregate metadata drift: %v", err)
				}
			})
		}
	}
}
