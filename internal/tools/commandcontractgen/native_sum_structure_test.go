package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/transactionresidue"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func TestResidueNativeStructuresRejectRehashedDrift(t *testing.T) {
	for id, schema := range map[string]func() map[string]any{
		"proofkit.transaction-inspect-residue.output.v1.json-schema":    transactionresidue.InspectionOutputStructure,
		"proofkit.transaction-quarantine-residue.output.v1.json-schema": transactionresidue.RelocationOutputStructure,
	} {
		owner, exists := nativeStructureOwner(id)
		if !exists || owner.direction != "output" || len(owner.commands) != 1 {
			t.Fatal("residue native owner is missing or ambiguous")
		}
		for _, mutation := range []string{"valid", "nullable-token", "open-root", "changed-claim", "wrong-version"} {
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			projected := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			if !reflect.DeepEqual(projected, schema()) {
				t.Fatal("native sum or output projection was flattened")
			}
			branch := projected
			if alternatives, ok := projected["oneOf"].([]any); ok {
				if len(alternatives) != 2 {
					t.Fatal("inspect sum lost a branch")
				}
				branch = alternatives[1].(map[string]any)
			}
			properties := branch["properties"].(map[string]any)
			switch mutation {
			case "nullable-token":
				properties["observationId"] = map[string]any{"type": "null"}
			case "open-root":
				branch["additionalProperties"] = true
			case "changed-claim":
				properties["nonClaims"].(map[string]any)["prefixItems"].([]any)[0].(map[string]any)["const"] = "proves no historical effects"
			case "wrong-version":
				properties["schemaVersion"].(map[string]any)["const"] = json.Number("2")
			}
			delete(definition, "canonicalDigest")
			encoded, err := canonicalJSON(definition)
			if err != nil {
				t.Fatal(err)
			}
			definition["canonicalDigest"] = sha256Digest(encoded)
			_, err = admitDefinitions(map[string]any{"contractDefinitions": []any{definition}})
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("%s/%s: %v", id, mutation, err)
			}
		}
	}
}

func TestNativeSumStructureRetainsBranchesAndRequiresOneRootIdentity(t *testing.T) {
	for _, mutation := range []string{"valid", "open", "missing-version", "wrong-version", "new-field", "optional-field", "scalar", "unknown-root"} {
		t.Run(mutation, func(t *testing.T) {
			schema := requirementcoverageview.OutputStructure()
			branch := schema["oneOf"].([]any)[1].(map[string]any)
			fields := branch["properties"].(map[string]any)
			switch mutation {
			case "open":
				branch["additionalProperties"] = true
			case "missing-version":
				delete(fields, "schemaVersion")
			case "wrong-version":
				fields["schemaVersion"].(map[string]any)["const"] = json.Number("5")
			case "new-field":
				fields["extra"] = map[string]any{"type": "string"}
			case "optional-field":
				branch["required"] = branch["required"].([]any)[1:]
			case "scalar":
				schema["oneOf"].([]any)[1] = map[string]any{"type": "string"}
			case "unknown-root":
				schema["nullable"] = true
			}
			owner := nativeStructure{id: "test.coverage.output.v4", direction: "output", schema: func() (map[string]any, error) { return schema, nil }}
			definition, err := owner.definition()
			if mutation != "valid" {
				if err == nil {
					t.Fatal("ambiguous/open root admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
			if !reflect.DeepEqual(variant["schema"], schema) {
				t.Fatal("sum was flattened")
			}
			version, err := nativeSchemaVersion(schema)
			if err != nil || version != "4" {
				t.Fatalf("version=%v: %v", version, err)
			}
		})
	}
}

func TestCoverageOutputStructurePreservesBothCLIOutputModes(t *testing.T) {
	var owner nativeStructure
	for _, candidate := range nativeStructures() {
		if candidate.id == "proofkit.requirement-coverage-view.output.v4.json-schema" {
			owner = candidate
			break
		}
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	version, err := owner.contractVersion(definition)
	if err != nil || version != "4" {
		t.Fatalf("coverage command version=%s, error=%v", version, err)
	}
	owner.wireVersion = "5"
	if _, err := owner.contractVersion(definition); err == nil {
		t.Fatal("unrepresented wire version was accepted")
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if len(variants) != 2 {
		t.Fatalf("coverage modes=%d, want envelope and report", len(variants))
	}
	envelope := variants[0].(map[string]any)
	report := variants[1].(map[string]any)
	if envelope["variantId"] != "01-agent-envelope" || report["variantId"] != "02-report" ||
		!reflect.DeepEqual(envelope["when"], []any{"--agent-envelope"}) ||
		!reflect.DeepEqual(report["when"], []any{"without --agent-envelope"}) ||
		!reflect.DeepEqual(report["schema"], requirementcoverageview.OutputStructure()) {
		t.Fatal("coverage output variants lost their owner or invocation condition")
	}
	actual := agentenvelope.Build(agentenvelope.Input{})
	wantFields := make([]any, 0, len(actual))
	for _, key := range sortedKeys(actual) {
		wantFields = append(wantFields, key)
	}
	if !reflect.DeepEqual(envelope["allowedFields"], wantFields) ||
		!reflect.DeepEqual(envelope["requiredFields"], wantFields) {
		t.Fatal("envelope root fields differ from the generic envelope owner")
	}
	for _, key := range []string{"bounds", "sourceReport"} {
		if envelope["schema"].(map[string]any)["properties"].(map[string]any)[key].(map[string]any)["type"] != "object" {
			t.Fatalf("envelope %s root type drifted", key)
		}
	}
}
