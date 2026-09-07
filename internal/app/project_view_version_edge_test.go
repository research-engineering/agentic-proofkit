package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// Normalize only the exact declared text delta. The cumulative ABI fingerprint
// oracle still checks every other predecessor field and definition unchanged.
func normalizeProjectContextPublicABIDelta(current map[string]any) error {
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	values := slices.Clone(current["commands"].([]any))
	for _, name := range []string{"requirement-context-slice", "requirement-traceability-graph"} {
		command, ok := commands[name]
		if !ok {
			return fmt.Errorf("project-context consumer is missing")
		}
		command = clonePublicABIRecord(command)
		input, ok := command["inputContract"].(map[string]any)
		if !ok {
			return fmt.Errorf("project-context consumer input contract is missing")
		}
		input = clonePublicABIRecord(input)
		command["inputContract"] = input
		summary, ok := input["compatibilitySummary"].([]any)
		if !ok || len(summary) < 4 || summary[2] != "context=proofkit.requirement-context schemaVersion=2 with strict v1 adapter, or schemaVersion=3 closed captured project origin" || summary[3] != "Project-origin v3 replay validates the exact canonical project and role/source partition; it does not reread live files or reinterpret the existing v1/v2 identities." {
			return fmt.Errorf("project-context compatibility differs from its declared delta")
		}
		references, ok := input["ownerRequirementRefs"].([]any)
		if !ok || len(references) == 0 || references[len(references)-1] != "REQ-PROOFKIT-SPEC-042" {
			return fmt.Errorf("project-context owner reference differs from its declared delta")
		}
		input["compatibilitySummary"] = slices.Concat(summary[:2], []any{"context=proofkit.requirement-context schemaVersion=2 with strict v1 adapter"}, summary[4:])
		input["ownerRequirementRefs"] = references[:len(references)-1]
		if name == "requirement-context-slice" {
			output, ok := command["outputContract"].(map[string]any)
			if !ok {
				return fmt.Errorf("project-context slice output contract is missing")
			}
			output = clonePublicABIRecord(output)
			command["outputContract"] = output
			summary, ok := output["compatibilitySummary"].([]any)
			if !ok || len(summary) < 2 || summary[1] != "Source-level nonClaims are retained separately in fragments from project-origin v3; v1/v2 fragment fields remain unchanged." {
				return fmt.Errorf("project-context slice output differs from its declared delta")
			}
			output["compatibilitySummary"] = slices.Concat(summary[:1], summary[2:])
		}
		for index, raw := range values {
			if raw.(map[string]any)["command"] == name {
				values[index] = command
			}
		}
	}
	current["commands"] = values
	return nil
}

func TestProjectViewVersionEdgePreservesCallerRecord(t *testing.T) {
	current := readCLIContractRaw(t)
	before, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyManagedIntegrationPublicABIDiff(readFrozenManagedIntegrationPredecessor(t), current); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(current)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("ABI delta oracle mutated its caller-owned contract")
	}
}

func TestProjectViewVersionEdgeRejectsContextContractDrift(t *testing.T) {
	for _, name := range []string{"requirement-context-slice", "requirement-traceability-graph"} {
		for _, field := range []string{"input-version", "input-replay", "input-owner", "output-restrictions"} {
			if field == "output-restrictions" && name != "requirement-context-slice" {
				continue
			}
			t.Run(name+"/"+field, func(t *testing.T) {
				current := readCLIContractRaw(t)
				mutatePublicABIRecord(t, current, "commands", "command", name, func(record map[string]any) {
					input := record["inputContract"].(map[string]any)
					switch field {
					case "input-version", "input-replay":
						index := 2
						if field == "input-replay" {
							index = 3
						}
						input["compatibilitySummary"].([]any)[index] = "undeclared drift"
					case "input-owner":
						references := input["ownerRequirementRefs"].([]any)
						references[len(references)-1] = "REQ-UNKNOWN"
					case "output-restrictions":
						record["outputContract"].(map[string]any)["compatibilitySummary"].([]any)[1] = "undeclared drift"
					}
				})
				if verifyManagedIntegrationPublicABIDiff(readFrozenManagedIntegrationPredecessor(t), current) == nil {
					t.Fatal("undeclared project context ABI delta was admitted")
				}
			})
		}
	}
}
