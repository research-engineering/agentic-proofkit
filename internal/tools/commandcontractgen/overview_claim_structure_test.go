package main

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/specoverviewclaims"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestOverviewClaimStructuresPreserveCurrentIdentities(t *testing.T) {
	input := specoverviewclaims.InputStructure()
	output := specoverviewclaims.OutputStructure()
	for _, item := range []struct {
		id     string
		schema map[string]any
		keys   []any
	}{
		{"proofkit.spec-overview-claims.input.v2.json-schema", input, []any{"boundaryId", "claims", "extractionRefs", "nonClaims", "overviewPath", "requirementIds", "requirementsPath", "schemaVersion", "sourceId", "specPackagePath"}},
		{"proofkit.spec-overview-claims.output.v1.json-schema", output, []any{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}},
	} {
		if item.schema["additionalProperties"] != false || !reflect.DeepEqual(item.schema["required"], item.keys) {
			t.Fatalf("%s is not a complete closed root", item.id)
		}
		found := false
		for _, structure := range nativeStructures() {
			if structure.id == item.id {
				found = true
				actual, err := structure.schema()
				if err != nil || !reflect.DeepEqual(actual, item.schema) {
					t.Fatalf("%s registry differs from its native owner: %v", item.id, err)
				}
			}
		}
		if !found {
			t.Fatalf("missing current identity %s", item.id)
		}
	}
}

func TestOverviewClaimRefreshRetainsStructuralSummaryAndPathRelation(t *testing.T) {
	source, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := refreshStructureSource(source, contract)
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
	if err != nil {
		t.Fatal(err)
	}
	input := commandAt(value.(map[string]any), "spec-overview-claims")["inputContract"].(map[string]any)
	want := []any{"schemaVersion=1", "structural JSON Schema definition proofkit.spec-overview-claims.input.v2.json-schema; canonicalization and semantic validity remain native admission obligations", "requirementsPath equals specPackagePath plus the requirement-source filename suffix"}
	if !reflect.DeepEqual(input["compatibilitySummary"], want) {
		t.Fatalf("path relation overrode the structural summary: %v", input["compatibilitySummary"])
	}
	if input["contractId"] != "proofkit.spec-overview-claims.input.v2" || !reflect.DeepEqual(input["pathRelations"], []any{specoverviewclaims.InputPathRelation()}) {
		t.Fatal("refresh changed the existing semantic identity or path relation")
	}
	repeated, err := refreshStructureSource(updated, value.(map[string]any))
	if err != nil || !bytes.Equal(updated, repeated) {
		t.Fatalf("refresh is not byte-idempotent: %v", err)
	}
}
