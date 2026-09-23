package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

// RawMessage preserves unrelated records and their key order. Only native-owned
// definitions and their consumer references are reconstructed on refresh.
type contractSource struct {
	SchemaVersion       json.RawMessage   `json:"schemaVersion"`
	ContractID          json.RawMessage   `json:"contractId"`
	PackageName         json.RawMessage   `json:"packageName"`
	ProcessContract     json.RawMessage   `json:"processContract"`
	Commands            []json.RawMessage `json:"commands"`
	ContractDefinitions []json.RawMessage `json:"contractDefinitions"`
}

func refreshStructures(root string) error {
	source, contract, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		return err
	}
	updated, err := refreshStructureSource(source, contract)
	if err != nil {
		return err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(updated), maxContractBytes)
	if err != nil {
		return err
	}
	app, presets, err := renderContract(root, updated, value.(map[string]any))
	if err != nil {
		return err
	}
	// All outputs are admitted and rendered before the first write. Atomicity is
	// per file; --check detects an interrupted multi-file refresh.
	for _, output := range []struct {
		path string
		data []byte
	}{{cliContractPath, updated}, {appGeneratedPath, app}, {presetGeneratedPath, presets}} {
		if err := writeAtomic(filepath.Join(root, output.path), output.data); err != nil {
			return err
		}
	}
	return nil
}

func refreshStructureSource(source []byte, contract map[string]any) ([]byte, error) {
	var wire contractSource
	if err := json.Unmarshal(source, &wire); err != nil {
		return nil, err
	}
	commands, ok := contract["commands"].([]any)
	if !ok || len(commands) != len(wire.Commands) {
		return nil, fmt.Errorf("CLI contract commands are invalid")
	}
	// Different owners may update the two directions of the same command.
	// Keep prior updates in a private outer slice rather than rereading the input.
	commands = slices.Clone(commands)
	definitions, ok := contract["contractDefinitions"].([]any)
	if !ok || len(definitions) != len(wire.ContractDefinitions) {
		return nil, fmt.Errorf("CLI contract definitions are invalid")
	}
	previous := ""
	for _, raw := range definitions {
		definition, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("CLI contract definition must be an object")
		}
		id, ok := definition["definitionId"].(string)
		if !ok || id == "" || id <= previous {
			return nil, fmt.Errorf("CLI contract definitions must be sorted and unique before refresh")
		}
		previous = id
	}
	replacements := map[string]json.RawMessage{}
	removed := map[string]bool{}
	for _, owner := range nativeStructures() {
		definition, err := owner.definition()
		if err != nil {
			return nil, err
		}
		version, err := owner.contractVersion(definition)
		if err != nil {
			return nil, err
		}
		count := 0
		for i, raw := range commands {
			command, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("CLI command must be an object")
			}
			name, _ := command["command"].(string)
			if !slices.Contains(owner.commands, name) {
				continue
			}
			key := owner.direction + "Contract"
			input, ok := command[key].(map[string]any)
			ref, _ := input["rootDefinitionRef"].(string)
			if !ok || (ref != owner.id && !slices.Contains(owner.predecessors, ref)) {
				return nil, fmt.Errorf("%s has no recognized native structure predecessor", name)
			}
			command, input = cloneRecord(command), cloneRecord(input)
			input["rootDefinitionRef"] = owner.id
			input["rootDefinitionDigest"] = definition["canonicalDigest"]
			input["contractId"] = "proofkit." + name + "." + owner.direction + ".v" + version.String()
			input["schemaVersion"] = version
			input["compatibilitySummary"] = owner.summary(version)
			command[key] = input
			commands[i] = command
			wire.Commands[i], err = encodeContractSource(command)
			if err != nil {
				return nil, err
			}
			count++
		}
		if count == 0 {
			continue
		}
		if count != len(owner.commands) {
			return nil, fmt.Errorf("native structure %s requires all consumers before refresh", owner.id)
		}
		encoded, err := encodeContractSource(definition)
		if err != nil {
			return nil, err
		}
		replacements[owner.id] = encoded
		for _, predecessor := range owner.predecessors {
			removed[predecessor] = true
		}
	}
	for i, raw := range definitions {
		definition, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("CLI contract definition must be an object")
		}
		id, ok := definition["definitionId"].(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("CLI contract definition has invalid identity")
		}
		if _, exists := replacements[id]; !exists && !removed[id] {
			replacements[id] = wire.ContractDefinitions[i]
		}
	}
	keys := sortedKeys(replacements)
	wire.ContractDefinitions = make([]json.RawMessage, 0, len(keys))
	for _, id := range keys {
		wire.ContractDefinitions = append(wire.ContractDefinitions, replacements[id])
	}
	encoded, err := encodeContractSource(wire)
	if err != nil {
		return nil, err
	}
	if len(encoded) > installedclicontract.MaximumContractBytes {
		return nil, fmt.Errorf("generated CLI contract exceeds installed carrier byte limit")
	}
	return encoded, nil
}

func encodeContractSource(value any) ([]byte, error) {
	var result bytes.Buffer
	encoder := json.NewEncoder(&result)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}
