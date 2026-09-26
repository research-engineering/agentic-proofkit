package app

import (
	"fmt"
	"strings"
	"testing"
)

var residueCommandAdditions = []struct {
	command    string
	definition string
}{
	{"transaction-inspect-residue", "proofkit.transaction-inspect-residue.output.v1.json-schema"},
	{"transaction-quarantine-residue", "proofkit.transaction-quarantine-residue.output.v1.json-schema"},
}

func verifyResidueDefinitionAdditions(previous, current map[string]map[string]any) error {
	for _, addition := range residueCommandAdditions {
		if _, exists := previous[addition.definition]; exists {
			return fmt.Errorf("declared residue definition already exists in predecessor")
		}
		if _, exists := current[addition.definition]; !exists {
			return fmt.Errorf("declared residue definition is missing")
		}
	}
	return nil
}

func TestResidueVersionEdgeRejectsUndeclaredInventory(t *testing.T) {
	previous := readArchivedSourceCutoverPredecessor(t)
	if _, err := sourceCutoverDirectionDelta(previous, readCLIContractRaw(t)); err != nil {
		t.Fatalf("unmodified current command inventory: %v", err)
	}
	for _, mutation := range []string{"missing-inspect", "missing-quarantine", "renamed", "extra", "order", "old-command-drift"} {
		t.Run(mutation, func(t *testing.T) {
			current := readCLIContractRaw(t)
			want := "public command inventory or order changed without declaration"
			switch mutation {
			case "missing-inspect":
				removePublicABIRecord(t, current, "commands", "command", residueCommandAdditions[0].command)
			case "missing-quarantine":
				removePublicABIRecord(t, current, "commands", "command", residueCommandAdditions[1].command)
			case "renamed":
				mutatePublicABIRecord(t, current, "commands", "command", residueCommandAdditions[0].command, func(record map[string]any) { record["command"] = "transaction-renamed" })
			case "extra":
				appendRenamedPublicABIRecord(t, current, "commands", "command", residueCommandAdditions[0].command, "transaction-unexpected")
			case "order":
				swapFirstPublicABIRecords(t, current, "commands")
			case "old-command-drift":
				mutatePublicABIRecord(t, current, "commands", "command", "impact", func(record map[string]any) { record["stdin"] = false })
				want = "impact command-level CLI behavior changed without declaration"
			}
			if _, err := sourceCutoverDirectionDelta(previous, current); err == nil || err.Error() != want {
				t.Fatalf("mutation rejected at wrong boundary: got %v, want %s", err, want)
			}
		})
	}
}

func TestResidueVersionEdgeRequiresBothDefinitions(t *testing.T) {
	previous, _, err := indexPublicABIRecords(readArchivedSourceCutoverPredecessor(t)["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := indexPublicABIRecords(readCLIContractRaw(t)["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyResidueDefinitionAdditions(previous, current); err != nil {
		t.Fatalf("unmodified definition additions: %v", err)
	}
	for _, addition := range residueCommandAdditions {
		t.Run(addition.command, func(t *testing.T) {
			record := current[addition.definition]
			delete(current, addition.definition)
			current["proofkit.unexpected.output.v1.json-schema"] = record
			err := verifyResidueDefinitionAdditions(previous, current)
			delete(current, "proofkit.unexpected.output.v1.json-schema")
			current[addition.definition] = record
			if err == nil || !strings.Contains(err.Error(), "declared residue definition is missing") {
				t.Fatalf("same-cardinality replacement admitted or wrong cause: %v", err)
			}
		})
	}
}
