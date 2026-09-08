package app

import (
	"fmt"
	"slices"
	"testing"
)

const inventoryInputGuideVersionSummary = "aggregate input contract v2; direct inventory schemaVersion=1; proof-binding-derived projection schemaVersion=2; discovery-draft projection schemaVersion=1"

// Only the admitted explanatory correction is normalized for historical ABI
// comparison. Every other field remains subject to the predecessor fingerprint.
func normalizeInventoryInputGuideContract(input map[string]any) (map[string]any, error) {
	summary, ok := input["compatibilitySummary"].([]any)
	if !ok || len(summary) == 0 || summary[0] != inventoryInputGuideVersionSummary {
		return nil, fmt.Errorf("inventory input version summary differs from its declared correction")
	}
	input = clonePublicABIRecord(input)
	summary = slices.Clone(summary)
	summary[0] = "schemaVersion=2"
	input["compatibilitySummary"] = summary
	return input, nil
}

func normalizeInventoryInputGuidePublicABIDelta(current map[string]any) error {
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	command, ok := commands["test-evidence-inventory"]
	if !ok {
		return fmt.Errorf("inventory command is missing")
	}
	input, ok := command["inputContract"].(map[string]any)
	if !ok {
		return fmt.Errorf("inventory input contract is missing")
	}
	input, err = normalizeInventoryInputGuideContract(input)
	if err != nil {
		return err
	}
	command = clonePublicABIRecord(command)
	command["inputContract"] = input
	values := slices.Clone(current["commands"].([]any))
	for index, raw := range values {
		if raw.(map[string]any)["command"] == "test-evidence-inventory" {
			values[index] = command
		}
	}
	current["commands"] = values
	return nil
}

func TestAdoptionInputGuideContractRejectsUndeclaredDelta(t *testing.T) {
	for _, mutation := range []string{"old-summary", "wrong-version", "missing-summary", "extra-summary", "other-field"} {
		t.Run(mutation, func(t *testing.T) {
			current := readCLIContractRaw(t)
			mutatePublicABIRecord(t, current, "commands", "command", "test-evidence-inventory", func(record map[string]any) {
				input := clonePublicABIRecord(record["inputContract"].(map[string]any))
				summary := slices.Clone(input["compatibilitySummary"].([]any))
				switch mutation {
				case "old-summary":
					summary[0] = "schemaVersion=2"
				case "wrong-version":
					summary[0] = "aggregate input contract v2; direct inventory schemaVersion=2"
				case "missing-summary":
					summary = summary[1:]
				case "extra-summary":
					summary = append(summary, "Undeclared semantics.")
				case "other-field":
					input["contractId"] = "proofkit.undeclared.input.v1"
				}
				input["compatibilitySummary"] = summary
				record["inputContract"] = input
			})
			if verifyManagedIntegrationPublicABIDiff(readFrozenManagedIntegrationPredecessor(t), current) == nil {
				t.Fatal("inventory correction hid an undeclared contract change")
			}
		})
	}
}
