package main

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestReceiptStructuresRejectRehashedNestedDrift(t *testing.T) {
	for _, command := range []string{"receipt-currentness-scope", "receipt-trust-class"} {
		for _, direction := range []string{"input", "output"} {
			id := "proofkit." + command + "." + direction + ".v1.json-schema"
			owner, ok := nativeStructureOwner(id)
			if !ok || !slices.Equal(owner.commands, []string{command}) || owner.direction != direction {
				t.Fatalf("wrong receipt structural owner: %s", id)
			}
			for _, mutation := range []string{"none", "nested-member", "nested-domain", "nested-cardinality"} {
				t.Run(command+"/"+direction+"/"+mutation, func(t *testing.T) {
					definition, err := owner.definition()
					if err != nil {
						t.Fatal(err)
					}
					pristine, err := owner.definition()
					if err != nil {
						t.Fatal(err)
					}
					schema := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
					fields := schema["properties"].(map[string]any)
					array := fields["ruleResults"]
					key := "ruleId"
					if direction == "input" {
						array, key = fields["obligationReceipts"], "obligationId"
					}
					items := array.(map[string]any)
					record := items["items"].(map[string]any)
					switch mutation {
					case "nested-member":
						record["required"] = []any{}
					case "nested-domain":
						record["properties"].(map[string]any)[key] = map[string]any{"type": "string"}
					case "nested-cardinality":
						items["minItems"] = 0
					}
					fresh, err := owner.definition()
					if err != nil || !reflect.DeepEqual(fresh, pristine) {
						t.Fatal("caller mutation changed the native structural owner")
					}
					delete(definition, "canonicalDigest")
					encoded, err := canonicalJSON(definition)
					if err != nil {
						t.Fatal(err)
					}
					definition["canonicalDigest"] = sha256Digest(encoded)
					err = admitNativeStructureDefinition(id, definition)
					if (err == nil) != (mutation == "none") {
						t.Fatalf("rehashed nested drift: %v", err)
					}
				})
			}
		}
	}
}

func TestReceiptChildBindingsPreserveOwnersInStructuredParent(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	const command = "selective-gate-obligation-decision-input"
	direction := commandAt(contract, command)["inputContract"].(map[string]any)
	root := definitions[direction["rootDefinitionRef"].(string)]
	if root.Content["fieldTree"].(map[string]any)["kind"] != "structural_json_schema" {
		t.Fatal("selective projection parent lacks its owned structure")
	}
	bindings := direction["childDefinitionBindings"].([]any)
	if len(bindings) != 3 {
		t.Fatalf("unexpected receipt child count: %d", len(bindings))
	}
	for i, expected := range []struct{ field, definition string }{
		{"receiptCurrentnessScopeAdmission", "proofkit.receipt-currentness-scope.input.v1.json-schema"},
		{"receiptTrustClassAdmission", "proofkit.receipt-trust-class.input.v1.json-schema"},
		{"evidence", "proofkit.selective-gate-evidence.input.v1.json-schema"},
	} {
		binding := bindings[i].(map[string]any)
		if binding["definitionRef"] != expected.definition || !reflect.DeepEqual(binding["pathSegments"], []any{expected.field}) {
			t.Fatalf("wrong child operand: %#v", binding)
		}
		for _, mutation := range []string{"missing", "field", "digest"} {
			candidate := cloneRecord(direction)
			children := slices.Clone(bindings)
			children[i] = cloneRecord(bindings[i].(map[string]any))
			candidate["childDefinitionBindings"] = children
			switch mutation {
			case "missing":
				candidate["childDefinitionBindings"] = append(children[:i], children[i+1:]...)
			case "field":
				children[i].(map[string]any)["pathSegments"] = []any{"unrelated"}
			case "digest":
				children[i].(map[string]any)["definitionDigest"] = "sha256:wrong"
			}
			if admitChildBindings(command, "input", candidate, root, definitions) == nil {
				t.Fatalf("admitted %s child %s", mutation, expected.field)
			}
		}
	}
}
