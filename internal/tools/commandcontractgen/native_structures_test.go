package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

func TestNativeStructureDefinitionOwnsCompleteProjection(t *testing.T) {
	owner := nativeStructures()[0]
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	if err := admitStructuralDefinition(owner.id, definition); err != nil {
		t.Fatal(err)
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(variant["schema"], requirementbinding.InputStructure()) {
		t.Fatal("wire schema differs from native owner")
	}
	if !reflect.DeepEqual(variant["requiredFields"], []any{"bindingId", "bindings", "nonClaims", "requirements", "schemaVersion", "witnessCommands"}) {
		t.Fatalf("wrong independent root summary: %v", variant["requiredFields"])
	}
	for _, mutation := range []string{"nested-type", "required-root", "unknown-owner", "version", "legacy-kind"} {
		t.Run(mutation, func(t *testing.T) {
			row, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			tree := row["fieldTree"].(map[string]any)
			variant := tree["variants"].([]any)[0].(map[string]any)
			switch mutation {
			case "nested-type":
				variant["schema"].(map[string]any)["properties"].(map[string]any)["nonClaims"].(map[string]any)["items"] = map[string]any{"type": "boolean"}
			case "required-root":
				variant["requiredFields"] = []any{}
			case "unknown-owner":
				row["definitionId"] = "proofkit.unknown.input.v1.json-schema"
			case "version":
				row["schemaVersion"] = json.Number("3")
			case "legacy-kind":
				tree["kind"] = "root_shape_only"
			}
			delete(row, "canonicalDigest")
			encoded, err := canonicalJSON(row)
			if err != nil {
				t.Fatal(err)
			}
			row["canonicalDigest"] = sha256Digest(encoded)
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{row}}); err == nil {
				t.Fatal("coherently rehashed schema drift was accepted")
			}
		})
	}
}

func TestNativeStructureConsumersAreClosed(t *testing.T) {
	owner := nativeStructures()[0]
	for _, mutation := range []string{"valid", "missing", "fourth", "output", "partial", "orphan", "obsolete"} {
		t.Run(mutation, func(t *testing.T) {
			commands := []any{}
			for _, name := range owner.commands {
				commands = append(commands, map[string]any{"command": name, "inputContract": map[string]any{"rootDefinitionRef": owner.id}})
			}
			definitions := map[string]definitionRecord{owner.id: {ID: owner.id}}
			switch mutation {
			case "missing":
				commands = commands[1:]
			case "fourth":
				commands = append(commands, map[string]any{"command": "other", "inputContract": map[string]any{"rootDefinitionRef": owner.id}})
			case "output":
				commands[0].(map[string]any)["outputContract"] = map[string]any{"rootDefinitionRef": owner.id}
			case "partial":
				commands[0].(map[string]any)["inputContract"].(map[string]any)["rootDefinitionRef"] = owner.predecessors[0]
			case "orphan":
				commands = []any{}
			case "obsolete":
				definitions[owner.predecessors[0]] = definitionRecord{ID: owner.predecessors[0]}
			}
			err := admitNativeStructureConsumers(map[string]any{"commands": commands}, definitions)
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("consumer admission error: %v", err)
			}
		})
	}
}

func TestStructureRefreshPreservesUnrelatedRecordsAndIsIdempotent(t *testing.T) {
	root := writeNativeStructureFixture(t)
	source, before, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := canonicalJSON(before)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := refreshStructureSource(source, before)
	if err != nil {
		t.Fatal(err)
	}
	afterValue, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
	if err != nil {
		t.Fatal(err)
	}
	after := afterValue.(map[string]any)
	unchanged, err := canonicalJSON(before)
	if err != nil || !bytes.Equal(beforeBytes, unchanged) {
		t.Fatal("refresh mutated caller-owned records")
	}
	owner := nativeStructures()[0]
	for _, raw := range before["commands"].([]any) {
		old := raw.(map[string]any)
		name := old["command"].(string)
		next := commandAt(after, name)
		if slices.Contains(owner.commands, name) {
			next = cloneRecord(next)
			input := cloneRecord(next["inputContract"].(map[string]any))
			oldInput := old["inputContract"].(map[string]any)
			for _, key := range []string{"rootDefinitionRef", "rootDefinitionDigest", "compatibilitySummary"} {
				input[key] = oldInput[key]
			}
			next["inputContract"] = input
		}
		if !reflect.DeepEqual(old, next) {
			t.Fatalf("refresh changed unowned command fields: %s", name)
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, updated); err != nil {
		t.Fatal(err)
	}
	if len(updated) > installedclicontract.MaximumContractBytes || !bytes.Equal(compact.Bytes(), bytes.TrimSpace(updated)) {
		t.Fatal("refreshed machine contract is not compact or exceeds its installed carrier bound")
	}
	oldDefinitions, err := admitDefinitions(before)
	if err != nil {
		t.Fatal(err)
	}
	newDefinitions, err := admitDefinitions(after)
	if err != nil {
		t.Fatal(err)
	}
	for id, old := range oldDefinitions {
		if id != owner.predecessors[0] && !reflect.DeepEqual(old, newDefinitions[id]) {
			t.Fatalf("unrelated definition changed: %s", id)
		}
	}
	if len(newDefinitions) != len(oldDefinitions) {
		t.Fatal("definition inventory changed beyond one-for-one replacement")
	}
	again, err := refreshStructureSource(updated, after)
	if err != nil || !bytes.Equal(updated, again) {
		t.Fatalf("refresh is not byte-idempotent: %v", err)
	}
	if err := refreshStructures(root); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}
}

func TestStructureRefreshRejectsDuplicatesAndValidatesBeforeWriting(t *testing.T) {
	for _, mutation := range []string{"duplicate-definition", "missing-consumer", "invalid-source"} {
		t.Run(mutation, func(t *testing.T) {
			root := writeNativeStructureFixture(t)
			contract := readFixtureContract(t, root)
			switch mutation {
			case "duplicate-definition":
				defs := contract["contractDefinitions"].([]any)
				contract["contractDefinitions"] = append(defs[:1:1], defs...)
			case "missing-consumer":
				commands := contract["commands"].([]any)
				contract["commands"] = slices.DeleteFunc(commands, func(raw any) bool { return raw.(map[string]any)["command"] == "proof-slice" })
			case "invalid-source":
				commandAt(contract, "sample")["inputContract"].(map[string]any)["nativeSource"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("0", 64)
			}
			writeFixtureContract(t, root, contract)
			before, err := os.ReadFile(filepath.Join(root, cliContractPath))
			if err != nil {
				t.Fatal(err)
			}
			if err := refreshStructures(root); err == nil {
				t.Fatal("invalid refresh succeeded")
			}
			after, err := os.ReadFile(filepath.Join(root, cliContractPath))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected refresh wrote contract")
			}
			for _, path := range []string{appGeneratedPath, presetGeneratedPath} {
				if _, err := os.Stat(filepath.Join(root, path)); !os.IsNotExist(err) {
					t.Fatalf("rejected refresh wrote projection: %s", path)
				}
			}
		})
	}
}

func writeNativeStructureFixture(t *testing.T) string {
	t.Helper()
	root := writeFixture(t)
	contract := readFixtureContract(t, root)
	owner := nativeStructures()[0]
	contract["contractDefinitions"] = append(contract["contractDefinitions"].([]any), structuralFixtureDefinition(owner.predecessors[0]))
	sample := commandAt(contract, "sample")
	for _, name := range owner.commands {
		command := cloneRecord(sample)
		command["command"] = name
		delete(command, "route")
		for _, direction := range []string{"input", "output"} {
			binding := cloneRecord(sample[direction+"Contract"].(map[string]any))
			binding["contractId"] = "proofkit." + name + "." + direction + ".v1"
			if direction == "input" {
				binding["rootDefinitionRef"] = owner.predecessors[0]
			}
			command[direction+"Contract"] = binding
		}
		contract["commands"] = append(contract["commands"].([]any), command)
	}
	slices.SortFunc(contract["contractDefinitions"].([]any), func(a, b any) int {
		return strings.Compare(a.(map[string]any)["definitionId"].(string), b.(map[string]any)["definitionId"].(string))
	})
	slices.SortFunc(contract["commands"].([]any), func(a, b any) int {
		return strings.Compare(a.(map[string]any)["command"].(string), b.(map[string]any)["command"].(string))
	})
	refreshDefinitionDigests(contract)
	refreshRootDefinitionDigests(contract)
	writeFixtureContract(t, root, contract)
	return root
}
