package app

import (
	"fmt"
	"strings"
	"testing"
)

// The conversion command is one reviewed addition to the archived predecessor
// ABI: one command and exactly its own input and output definitions.
var sourceConversionCommandAddition = struct {
	command     string
	definitions []string
}{
	command: "requirement-source-conversion",
	definitions: []string{
		"proofkit.requirement-source-conversion.input.v1.json-schema",
		"proofkit.requirement-source-conversion.output.v1.json-schema",
	},
}

func verifySourceConversionDefinitionAdditions(previous, current map[string]map[string]any) error {
	for _, definition := range sourceConversionCommandAddition.definitions {
		if _, exists := previous[definition]; exists {
			return fmt.Errorf("declared conversion definition already exists in predecessor")
		}
		if _, exists := current[definition]; !exists {
			return fmt.Errorf("declared conversion definition is missing")
		}
	}
	return nil
}

func TestSourceConversionVersionEdgeRejectsUndeclaredInventory(t *testing.T) {
	previous := readArchivedSourceCutoverPredecessor(t)
	if _, err := sourceCutoverDirectionDelta(previous, readCLIContractRaw(t)); err != nil {
		t.Fatalf("unmodified current command inventory: %v", err)
	}
	for _, mutation := range []string{"missing", "renamed", "duplicate-addition"} {
		t.Run(mutation, func(t *testing.T) {
			current := readCLIContractRaw(t)
			switch mutation {
			case "missing":
				removePublicABIRecord(t, current, "commands", "command", sourceConversionCommandAddition.command)
			case "renamed":
				mutatePublicABIRecord(t, current, "commands", "command", sourceConversionCommandAddition.command, func(record map[string]any) {
					record["command"] = "requirement-source-converter"
				})
			case "duplicate-addition":
				appendRenamedPublicABIRecord(t, current, "commands", "command", sourceConversionCommandAddition.command, "requirement-source-import")
			}
			want := "public command inventory or order changed without declaration"
			if _, err := sourceCutoverDirectionDelta(previous, current); err == nil || err.Error() != want {
				t.Fatalf("mutation rejected at wrong boundary: got %v, want %s", err, want)
			}
		})
	}
}

func TestSourceConversionVersionEdgeRequiresBothDefinitions(t *testing.T) {
	previous, _, err := indexPublicABIRecords(readArchivedSourceCutoverPredecessor(t)["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := indexPublicABIRecords(readCLIContractRaw(t)["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySourceConversionDefinitionAdditions(previous, current); err != nil {
		t.Fatalf("unmodified definition additions: %v", err)
	}
	for _, definition := range sourceConversionCommandAddition.definitions {
		t.Run(definition, func(t *testing.T) {
			record := current[definition]
			delete(current, definition)
			current["proofkit.unexpected.output.v1.json-schema"] = record
			err := verifySourceConversionDefinitionAdditions(previous, current)
			delete(current, "proofkit.unexpected.output.v1.json-schema")
			current[definition] = record
			if err == nil || !strings.Contains(err.Error(), "declared conversion definition is missing") {
				t.Fatalf("same-cardinality replacement admitted or wrong cause: %v", err)
			}
		})
	}
}
