package app

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

const canonicalPathContractPolicy = "Current path equivalence is Unicode 17 canonical caseless matching (D145); fresh plans and journals use transaction schemaVersion=3. Retained transaction versions 1 and 2 preserve their original path equivalence and recovery identities; receipt schemaVersion=2 is independent."

func verifyCanonicalPathContracts(contract map[string]any) error {
	commands, _, err := indexPublicABIRecords(contract["commands"], "command")
	if err != nil {
		return err
	}
	for _, name := range []string{"adopt-materialize-apply", "adopt-materialize-plan", "adopt-materialize-recover", "integration-apply", "integration-plan", "integration-recover"} {
		command, ok := commands[name]
		if !ok {
			return fmt.Errorf("missing canonical-path command %s", name)
		}
		for _, direction := range []string{"input", "output"} {
			wireVersion, semanticVersion := "1", "2"
			if direction == "input" {
				if name != "adopt-materialize-apply" && name != "adopt-materialize-plan" {
					continue
				}
				wireVersion, semanticVersion = "2", "3"
			}
			value, ok := command[direction+"Contract"].(map[string]any)
			if !ok || value["schemaVersion"] != json.Number(wireVersion) || value["contractId"] != "proofkit."+name+"."+direction+".v"+semanticVersion {
				return fmt.Errorf("canonical path semantic/wire identity mismatch: %s %s", name, direction)
			}
			summary, ok := value["compatibilitySummary"].([]any)
			if !ok || len(summary) == 0 || summary[len(summary)-1] != canonicalPathContractPolicy {
				return fmt.Errorf("canonical path policy missing: %s %s", name, direction)
			}
			sources, ok := value["nativeSources"].([]any)
			if !ok {
				return fmt.Errorf("canonical path native closure missing: %s %s", name, direction)
			}
			paths := make([]string, 0, len(sources))
			for _, source := range sources {
				entry, ok := source.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid native source")
				}
				path, ok := entry["path"].(string)
				if !ok {
					return fmt.Errorf("invalid native source path")
				}
				paths = append(paths, path)
			}
			for _, owner := range []string{"internal/kernel/pathidentity", "internal/kernel/repositorytransaction", "internal/kernel/rootpath"} {
				if !slices.Contains(paths, owner) {
					return fmt.Errorf("canonical path owner missing: %s", owner)
				}
			}
		}
	}
	return nil
}

func TestCanonicalPathContractIdentitySeparatesWireVersion(t *testing.T) {
	current := readCLIContractRaw(t)
	if err := verifyCanonicalPathContracts(current); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"old-input-identity", "wire-version-churn", "missing-policy", "missing-path-owner", "old-plan-output-identity"} {
		t.Run(mutation, func(t *testing.T) {
			changed := clonePublicABIRecord(current)
			commands, _, err := indexPublicABIRecords(changed["commands"], "command")
			if err != nil {
				t.Fatal(err)
			}
			input := commands["adopt-materialize-plan"]["inputContract"].(map[string]any)
			switch mutation {
			case "old-input-identity":
				input["contractId"] = "proofkit.adopt-materialize-plan.input.v2"
			case "wire-version-churn":
				input["schemaVersion"] = json.Number("3")
			case "missing-policy":
				summary := input["compatibilitySummary"].([]any)
				input["compatibilitySummary"] = summary[:len(summary)-1]
			case "missing-path-owner":
				sources := input["nativeSources"].([]any)
				input["nativeSources"] = slices.DeleteFunc(sources, func(raw any) bool {
					return raw.(map[string]any)["path"] == "internal/kernel/pathidentity"
				})
			case "old-plan-output-identity":
				commands["integration-plan"]["outputContract"].(map[string]any)["contractId"] = "proofkit.integration-plan.output.v1"
			}
			if verifyCanonicalPathContracts(changed) == nil {
				t.Fatal("contract boundary mutation was admitted")
			}
		})
	}
}
