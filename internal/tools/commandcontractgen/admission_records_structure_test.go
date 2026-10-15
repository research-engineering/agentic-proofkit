package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/deploymentevidenceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/repoprofileadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/specproofbundleadmission"
)

var admissionRecordOwners = []struct {
	command, direction string
	build              func() map[string]any
}{
	{"capability-map-admission", "input", capabilitymapadmission.InputStructure},
	{"capability-map-admission", "output", capabilitymapadmission.OutputStructure},
	{"deployment-evidence-admission", "input", deploymentevidenceadmission.InputStructure},
	{"deployment-evidence-admission", "output", deploymentevidenceadmission.OutputStructure},
	{"repo-profile-admission", "input", repoprofileadmission.InputStructure},
	{"repo-profile-admission", "output", repoprofileadmission.OutputStructure},
	{"spec-proof-bundle-admission", "input", specproofbundleadmission.InputStructure},
	{"spec-proof-bundle-admission", "output", specproofbundleadmission.OutputStructure},
}

func TestAdmissionRecordStructuresConserveIdentityAndRetirePredecessors(t *testing.T) {
	contract := readFixtureContract(t, filepath.Join("..", "..", ".."))
	published := map[string]map[string]any{}
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		published[definition["definitionId"].(string)] = definition
	}
	for _, row := range admissionRecordOwners {
		id := "proofkit." + row.command + "." + row.direction + ".v1.json-schema"
		predecessor := "proofkit." + row.command + "." + row.direction + ".v1.root-shape"
		owner, ok := nativeStructureOwner(id)
		if !ok || owner.direction != row.direction || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{predecessor}) {
			t.Fatalf("wrong native owner binding: %s", id)
		}
		if owner.optionalInputVersion != (row.command == "repo-profile-admission" && row.direction == "input") ||
			owner.semanticVersion != 0 || owner.aggregateVersion != "" || owner.wireVersion != "" || owner.outOfBandVersion != "" || len(owner.variants) != 0 {
			t.Fatalf("version authority drifted: %s", id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		if err := admitNativeStructureDefinition(id, definition); err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number("1") || owner.contractID(row.command, version) != "proofkit."+row.command+"."+row.direction+".v1" {
			t.Fatalf("contract identity drifted: %s %s %v", id, version, err)
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		if len(variants) != 1 || variants[0].(map[string]any)["variantId"] != "01-root" || !reflect.DeepEqual(variants[0].(map[string]any)["when"], []any{"default JSON mode"}) {
			t.Fatalf("predecessor variant partition changed: %s", id)
		}
		if !equalPublishedSchema(variants[0].(map[string]any)["schema"], row.build()) {
			t.Fatalf("schema is not native-owner derived: %s", id)
		}
		if _, exists := published[predecessor]; exists {
			t.Fatalf("obsolete predecessor %s remains", predecessor)
		}
		binding := commandAt(contract, row.command)[row.direction+"Contract"].(map[string]any)
		if binding["rootDefinitionRef"] != id || binding["rootDefinitionDigest"] != definition["canonicalDigest"] ||
			binding["contractId"] != "proofkit."+row.command+"."+row.direction+".v1" || binding["schemaVersion"] != json.Number("1") {
			t.Fatalf("published consumer binding drifted: %s", id)
		}
		canonicalPublished, err := canonicalJSON(published[id])
		if err != nil {
			t.Fatal(err)
		}
		canonicalOwner, err := canonicalJSON(definition)
		if err != nil || string(canonicalPublished) != string(canonicalOwner) {
			t.Fatalf("published definition differs from owner: %s", id)
		}
		for _, mutation := range []string{"open", "required", "properties"} {
			changed, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			if branches, sum := schema["oneOf"].([]any); sum {
				schema = branches[len(branches)-1].(map[string]any)
			}
			switch mutation {
			case "open":
				schema["additionalProperties"] = true
			case "required":
				schema["required"] = []any{}
			case "properties":
				schema["properties"].(map[string]any)["schemaVersion"] = map[string]any{"type": "integer"}
			}
			delete(changed, "canonicalDigest")
			encoded, err := canonicalJSON(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed["canonicalDigest"] = sha256Digest(encoded)
			if admitNativeStructureDefinition(id, changed) == nil {
				t.Fatalf("accepted rehashed %s/%s drift", id, mutation)
			}
		}
	}
}

func TestRepoProfileTransitionalVersionRemainsOptional(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.repo-profile-admission.input.v1.json-schema")
	if !ok {
		t.Fatal("missing repo profile owner")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if !slices.Contains(variant["allowedFields"].([]any), any("schemaVersion")) || slices.Contains(variant["requiredFields"].([]any), any("schemaVersion")) {
		t.Fatal("transitional schemaVersion became required or disappeared")
	}
	owner.optionalInputVersion = false
	if _, err := owner.contractVersion(definition); err == nil {
		t.Fatal("required-version authority accepted an optional header")
	}
}

func TestSpecProofBundleChildrenBindPublishedOwners(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	input := commandAt(contract, "spec-proof-bundle-admission")["inputContract"].(map[string]any)
	root := definitions[input["rootDefinitionRef"].(string)]
	if err := admitChildBindings("spec-proof-bundle-admission", "input", input, root, definitions); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"requirementBindings": "proofkit.requirement-bindings.input.v1.json-schema", "witnessPlan": "proofkit.witness-scheduler-plan.input.v1.json-schema",
		"receiptAdmission/report":         "proofkit.proof-receipt-admission.output.v1.json-schema",
		"receiptProducerAdmission/report": "proofkit.receipt-producer-admission.output.v1.json-schema",
	}
	bindings := input["childDefinitionBindings"].([]any)
	if len(bindings) != len(want) {
		t.Fatalf("child binding set drifted: %v", bindings)
	}
	for _, raw := range bindings {
		binding := raw.(map[string]any)
		path := ""
		for index, segment := range binding["pathSegments"].([]any) {
			if index > 0 {
				path += "/"
			}
			path += segment.(string)
		}
		if want[path] != binding["definitionRef"] || binding["definitionDigest"] != definitions[want[path]].Digest {
			t.Fatalf("child %s is not bound to its published owner", path)
		}
	}
	for _, field := range []string{"", "receiptAdmission", "receiptProducerAdmission", "requirementBindings", "witnessPlan"} {
		encoded, err := canonicalJSON(root.Content)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		var copy map[string]any
		if err := decoder.Decode(&copy); err != nil {
			t.Fatal(err)
		}
		schema := copy["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
		switch field {
		case "":
		case "receiptAdmission", "receiptProducerAdmission":
			child := schema["properties"].(map[string]any)[field].(map[string]any)["anyOf"].([]any)[1].(map[string]any)
			child["properties"].(map[string]any)["report"].(map[string]any)["description"] = "Forked child report."
		default:
			schema["properties"].(map[string]any)[field].(map[string]any)["additionalProperties"] = true
		}
		err = admitChildBindings("spec-proof-bundle-admission", "input", input, definitionRecord{ID: root.ID, Digest: root.Digest, Content: copy}, definitions)
		if (err == nil) != (field == "") {
			t.Fatalf("child owner fork %q changed binding admission: %v", field, err)
		}
	}
}
