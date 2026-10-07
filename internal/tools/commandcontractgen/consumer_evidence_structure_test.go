package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/externalconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumerinputcompose"
)

func TestConsumerEvidenceStructuresBindAllSixNativeDirections(t *testing.T) {
	owners := map[string]func() map[string]any{
		"external-consumer.input": externalconsumer.InputStructure, "external-consumer.output": externalconsumer.OutputStructure,
		"registry-consumer.input": registryconsumer.InputStructure, "registry-consumer.output": registryconsumer.OutputStructure,
		"registry-consumer-proof-input-compose.input": registryconsumerinputcompose.InputStructure, "registry-consumer-proof-input-compose.output": registryconsumerinputcompose.OutputStructure,
	}
	for name, build := range owners {
		want := build()
		version, semanticVersion := "1", uint(0)
		if strings.HasSuffix(name, ".input") {
			version, semanticVersion = "2", 2
		}
		found := 0
		for _, structure := range nativeStructures() {
			if structure.id != "proofkit."+name+".v"+version+".json-schema" {
				continue
			}
			found++
			actual, err := structure.schema()
			if err != nil || !reflect.DeepEqual(actual, want) {
				t.Fatalf("%s projection differs from native owner: %v", name, err)
			}
			if structure.semanticVersion != semanticVersion || !reflect.DeepEqual(structure.predecessors, []string{"proofkit." + name + ".v1.root-shape"}) {
				t.Fatalf("%s changed existing identity or predecessor", name)
			}
		}
		if found != 1 {
			t.Fatalf("%s native owner count=%d, want1", name, found)
		}
	}
	composition := registryconsumerinputcompose.OutputStructure()["properties"].(map[string]any)["registryConsumerInput"].(map[string]any)["oneOf"].([]any)
	if len(composition) != 2 || !reflect.DeepEqual(composition[1], registryconsumer.InputStructure()) {
		t.Fatal("composer does not consume the registry-owned input projection")
	}
}
