package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestShardSemanticIdentityPreservesWireVersionAndRejectsOldIdentity(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	source, original, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := refreshStructureSource(source, original)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"input", "output"} {
		for _, mode := range []string{"unchanged", "old identity", "changed wire version", "missing owner"} {
			t.Run(direction+"/"+mode, func(t *testing.T) {
				value, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
				if err != nil {
					t.Fatal(err)
				}
				contract := value.(map[string]any)
				binding := commandAt(contract, "workspace-shard-partition")[direction+"Contract"].(map[string]any)
				prefix := "proofkit.workspace-shard-partition." + direction
				if binding["contractId"] != prefix+".v2" || binding["schemaVersion"] != json.Number("1") || binding["rootDefinitionRef"] != prefix+".v2.json-schema" {
					t.Fatalf("refresh conflated wire and semantic identities: %v", binding)
				}
				definitions, err := admitDefinitions(contract)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "old identity":
					binding["contractId"] = prefix + ".v1"
				case "changed wire version":
					binding["schemaVersion"] = json.Number("2")
				case "missing owner":
					delete(definitions, prefix+".v2.json-schema")
				}
				err = admitNativeStructureConsumers(contract, definitions)
				if (err == nil) != (mode == "unchanged") {
					t.Fatalf("consumer identity admission for %s: %v", mode, err)
				}
			})
		}
	}
}
