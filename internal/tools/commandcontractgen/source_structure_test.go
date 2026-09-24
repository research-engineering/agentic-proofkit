package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceStructureHasOneCodecOwnerAndExplicitWireVersion(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.requirement-source.input.v2.json-schema")
	if !ok {
		t.Fatal("grouped source has no native structural owner")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	schema, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil || !reflect.DeepEqual(variant["schema"], schema) {
		t.Fatal("source schema differs from codec")
	}
	if !reflect.DeepEqual(variant["requiredFields"], []any{"groups", "kind", "schemaVersion", "sourceId", "sourceNonClaims", "specPackagePath"}) {
		t.Fatalf("required source fields: %#v", variant["requiredFields"])
	}
	version, err := nativeSchemaVersion(schema)
	if err != nil || version != json.Number("2") {
		t.Fatalf("source wire version: %v, %v", version, err)
	}
	if !reflect.DeepEqual(owner.commands, []string{"requirement-source-admission", "requirement-source-view"}) {
		t.Fatal("source consumer set drift")
	}
	properties := schema["properties"].(map[string]any)
	group := properties["groups"].(map[string]any)["items"].(map[string]any)
	group["properties"].(map[string]any)["statementStem"] = map[string]any{"type": "boolean"}
	variant["schema"] = schema
	delete(definition, "canonicalDigest")
	encoded, err := canonicalJSON(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition["canonicalDigest"] = sha256Digest(encoded)
	if err := admitNativeStructureDefinition(owner.id, definition); err == nil {
		t.Fatal("rehashed nested source drift accepted")
	}
}

func TestNativeStructureRejectsCallbackAndVersionFailures(t *testing.T) {
	owner := nativeStructures()[0]
	for _, kind := range []string{"callback", "optional", "missing", "noncanonical", "zero", "wrong type"} {
		t.Run(kind, func(t *testing.T) {
			candidate := owner
			candidate.schema = func() (map[string]any, error) {
				if kind == "callback" {
					return nil, errors.New("fixture schema callback failed")
				}
				schema, err := owner.schema()
				if err != nil {
					return nil, err
				}
				version := schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)
				switch kind {
				case "optional":
					schema["required"] = []any{}
				case "missing":
					delete(version, "const")
				case "noncanonical":
					version["const"] = json.Number("01")
				case "zero":
					version["const"] = json.Number("0")
				case "wrong type":
					version["const"] = "1"
				}
				return schema, nil
			}
			if value, err := candidate.definition(); err == nil || value != nil {
				t.Fatal("invalid native schema emitted a definition")
			}
		})
	}
}

func TestSourceStructureRefreshUnifiesPredecessorsAndVersionsConsumers(t *testing.T) {
	root := writeSourceStructureFixture(t)
	owner, _ := nativeStructureOwner("proofkit.requirement-source.input.v2.json-schema")
	source, before, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := refreshStructureSource(source, before)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
	if err != nil {
		t.Fatal(err)
	}
	after := decoded.(map[string]any)
	if !reflect.DeepEqual(commandAt(before, "sample"), commandAt(after, "sample")) {
		t.Fatal("unrelated command changed")
	}
	for _, name := range owner.commands {
		input := commandAt(after, name)["inputContract"].(map[string]any)
		if input["contractId"] != "proofkit."+name+".input.v2" || input["schemaVersion"] != json.Number("2") || input["rootDefinitionRef"] != owner.id || input["compatibilitySummary"].([]any)[0] != "schemaVersion=2" {
			t.Fatalf("source contract identity drift: %#v", input)
		}
	}
	definitions, err := admitDefinitions(after)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range owner.predecessors {
		if _, ok := definitions[old]; ok {
			t.Fatal("retired source shape retained")
		}
	}
	if _, ok := definitions[owner.id]; !ok || len(after["contractDefinitions"].([]any)) != len(before["contractDefinitions"].([]any))-1 {
		t.Fatal("source shapes were not unified exactly")
	}
	if err := admitNativeStructureConsumers(after, definitions); err != nil {
		t.Fatal(err)
	}
	outputOwner, _ := nativeStructureOwner("proofkit.requirement-source-admission.output.v2.json-schema")
	output := commandAt(after, "requirement-source-admission")["outputContract"].(map[string]any)
	if output["rootDefinitionRef"] != outputOwner.id || output["contractId"] != "proofkit.requirement-source-admission.output.v2" || output["schemaVersion"] != json.Number("2") {
		t.Fatal("second direction did not retain both owner updates")
	}
	again, err := refreshStructureSource(updated, after)
	if err != nil || !bytes.Equal(updated, again) {
		t.Fatalf("source refresh is not idempotent: %v", err)
	}
}

func writeSourceStructureFixture(t *testing.T) string {
	t.Helper()
	root := writeFixture(t)
	contract := readFixtureContract(t, root)
	owner, _ := nativeStructureOwner("proofkit.requirement-source.input.v2.json-schema")
	sample := commandAt(contract, "sample")
	for i, name := range owner.commands {
		contract["contractDefinitions"] = append(contract["contractDefinitions"].([]any), structuralFixtureDefinition(owner.predecessors[i]))
		command := cloneRecord(sample)
		command["command"] = name
		delete(command, "route")
		input := cloneRecord(command["inputContract"].(map[string]any))
		input["contractId"], input["schemaVersion"] = "proofkit."+name+".input.v1", json.Number("1")
		input["rootDefinitionRef"] = owner.predecessors[i]
		command["inputContract"] = input
		{
			outputOwner, _ := nativeStructureOwner("proofkit." + name + ".output.v2.json-schema")
			contract["contractDefinitions"] = append(contract["contractDefinitions"].([]any), structuralFixtureDefinition(outputOwner.predecessors[0]))
			output := cloneRecord(command["outputContract"].(map[string]any))
			output["rootDefinitionRef"] = outputOwner.predecessors[0]
			output["contractId"], output["schemaVersion"] = "proofkit."+name+".output.v2", json.Number("2")
			command["outputContract"] = output
		}
		contract["commands"] = append(contract["commands"].([]any), command)
	}
	slices.SortFunc(contract["commands"].([]any), func(a, b any) int {
		return strings.Compare(a.(map[string]any)["command"].(string), b.(map[string]any)["command"].(string))
	})
	slices.SortFunc(contract["contractDefinitions"].([]any), func(a, b any) int {
		return strings.Compare(a.(map[string]any)["definitionId"].(string), b.(map[string]any)["definitionId"].(string))
	})
	refreshDefinitionDigests(contract)
	refreshRootDefinitionDigests(contract)
	writeFixtureContract(t, root, contract)
	return root
}

func TestNativeOutputOwnerRejectsDirectionAliasAndRehashedTupleDrift(t *testing.T) {
	root := writeSourceStructureFixture(t)
	content, before, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := refreshStructureSource(content, before)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := nativeStructureOwner("proofkit.requirement-source-admission.output.v2.json-schema")
	for _, mutation := range []string{"wrong direction", "other command", "tuple cardinality", "integer range"} {
		t.Run(mutation, func(t *testing.T) {
			value, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
			if err != nil {
				t.Fatal(err)
			}
			contract := value.(map[string]any)
			if mutation == "wrong direction" || mutation == "other command" {
				command, direction := "requirement-source-admission", "inputContract"
				if mutation == "other command" {
					command, direction = "sample", "outputContract"
				}
				commandAt(contract, command)[direction].(map[string]any)["rootDefinitionRef"] = owner.id
				definitions, err := admitDefinitions(contract)
				if err != nil {
					t.Fatal(err)
				}
				if err := admitNativeStructureConsumers(contract, definitions); err == nil {
					t.Fatal("output owner alias admitted")
				}
				return
			}
			for _, raw := range contract["contractDefinitions"].([]any) {
				definition := raw.(map[string]any)
				if definition["definitionId"] != owner.id {
					continue
				}
				properties := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)
				if mutation == "tuple cardinality" {
					delete(properties["ruleResults"].(map[string]any), "maxItems")
				} else {
					properties["summary"].(map[string]any)["properties"].(map[string]any)["failureCount"].(map[string]any)["minimum"] = json.Number("-1")
				}
			}
			refreshDefinitionDigests(contract)
			refreshRootDefinitionDigests(contract)
			if _, err := admitDefinitions(contract); err == nil {
				t.Fatal("rehashed output schema drift admitted")
			}
		})
	}
}
