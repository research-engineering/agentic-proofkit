package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestGradualStructureOwnersConserveSemanticAndWireIdentity(t *testing.T) {
	for _, command := range []string{"gradual-adoption", "gradual-adoption-guidance", "gradual-adoption-bootstrap"} {
		for _, direction := range []string{"input", "output"} {
			version := "1"
			if command == "gradual-adoption-bootstrap" && direction == "input" {
				version = "2"
			}
			id := "proofkit." + command + "." + direction + ".v" + version + ".json-schema"
			owner, exists := nativeStructureOwner(id)
			if !exists {
				t.Fatalf("missing owner %s", id)
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := owner.contractVersion(definition)
			if err != nil || wire != json.Number("1") || owner.contractID(command, wire) != "proofkit."+command+"."+direction+".v"+version {
				t.Fatalf("semantic/wire identity conflated: %s %s %v", id, wire, err)
			}
			if err := admitNativeStructureDefinition(id, definition); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestBootstrapAggregateConsumerIdentityCannotUseFallbackGuard(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"positive", "retired identity", "wrong wire version"} {
		value, err := admission.DecodeJSON(bytes.NewReader(source), maxContractBytes)
		if err != nil {
			t.Fatal(err)
		}
		contract := value.(map[string]any)
		definitions, err := admitDefinitions(contract)
		if err != nil {
			t.Fatal(err)
		}
		input := commandAt(contract, "gradual-adoption-bootstrap")["inputContract"].(map[string]any)
		switch mutation {
		case "retired identity":
			input["contractId"] = "proofkit.gradual-adoption-bootstrap.input.v1"
		case "wrong wire version":
			input["schemaVersion"] = json.Number("2")
		}
		err = admitNativeStructureConsumers(contract, definitions)
		if mutation == "positive" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "gradual-adoption-bootstrap input contract violates native semantic contract identity") {
			t.Fatalf("%s did not reach the exact native consumer guard: %v", mutation, err)
		}
	}
}

func TestGuidanceOverrideVariantsBindEveryIndependentOperand(t *testing.T) {
	variants := gradualGuidanceInputVariants()
	if len(variants) != 9 {
		t.Fatalf("override combinations omitted: %d", len(variants))
	}
	for mask := range 8 {
		got, err := variants[mask+1].schema()
		if err != nil {
			t.Fatal(err)
		}
		want := gradualadoption.GuidanceContractInputStructure(mask&1 != 0, mask&2 != 0, mask&4 != 0)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("override operand drift: %d", mask)
		}
	}
}
