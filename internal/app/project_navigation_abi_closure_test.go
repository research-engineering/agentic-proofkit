package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const archivedProjectNavigationContractSHA256 = "4a409dd87ab13fa3f3951c16438f1d0f1595cc0ca2f6a1e1317c5c0e2fc9801e"

func TestProjectNavigationVersionEdgeClosesCompletePublicABIDiff(t *testing.T) {
	if err := verifyCompleteProjectNavigationABIDiff(readFrozenProjectNavigationPublicABI(t), readArchivedProjectNavigationContract(t)); err != nil {
		t.Fatal(err)
	}
}

func readArchivedProjectNavigationContract(t *testing.T) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), archivedProjectNavigationReleaseRoot, "cli-contract.v2.json.zip"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 1 || archive.File[0].Name != "cli-contract.v2.json" || archive.File[0].UncompressedSize64 > 1<<20 {
		t.Fatal("archived CLI contract must contain exactly its bounded contract entry")
	}
	reader, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read archived CLI contract: %v; close: %v", err, closeErr)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != archivedProjectNavigationContractSHA256 {
		t.Fatalf("archived CLI contract changed: %s", got)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}
func verifyCompleteProjectNavigationABIDiff(frozen frozenPublicABI, current map[string]any) error {
	schemaVersion, err := admit.CanonicalInteger(current["schemaVersion"], "current CLI contract schemaVersion")
	if err != nil || int(schemaVersion) != frozen.ContractSchemaVersion || current["contractId"] != frozen.ContractID || current["packageName"] != frozen.PackageName {
		return fmt.Errorf("current CLI contract header differs from the frozen predecessor")
	}
	commands, commandOrder, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	if !slices.IsSorted(commandOrder) {
		return fmt.Errorf("current CLI command order is not canonical")
	}
	addedCommands := differenceKeys(commands, frozen.Commands)
	if !slices.Equal(addedCommands, []string{"next", "status"}) {
		return fmt.Errorf("current CLI contract has undeclared command additions: %v", addedCommands)
	}
	for name, wantDigest := range frozen.Commands {
		record, ok := commands[name]
		if !ok {
			return fmt.Errorf("current CLI contract removed predecessor command %s", name)
		}
		if name == "change-workflow-plan" {
			record = clonePublicABIRecord(record)
			delete(record, "route")
		}
		normalized, err := normalizePublicABICommandFingerprint(record)
		if err != nil {
			return fmt.Errorf("normalize current command %s: %w", name, err)
		}
		gotDigest, err := digest.StableJSONSHA256Ref(normalized)
		if err != nil {
			return fmt.Errorf("fingerprint current command %s: %w", name, err)
		}
		if gotDigest != wantDigest {
			return fmt.Errorf("current CLI command %s has undeclared ABI drift", name)
		}
	}

	definitions, definitionOrder, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		return err
	}
	if !slices.IsSorted(definitionOrder) {
		return fmt.Errorf("current CLI definition order is not canonical")
	}
	for id, wantDigest := range frozen.ContractDefinitions {
		record, ok := definitions[id]
		if !ok {
			return fmt.Errorf("current CLI contract removed predecessor definition %s", id)
		}
		gotDigest, err := digest.StableJSONSHA256Ref(record)
		if err != nil {
			return fmt.Errorf("fingerprint current definition %s: %w", id, err)
		}
		if gotDigest != wantDigest {
			return fmt.Errorf("current CLI definition %s has undeclared ABI drift", id)
		}
	}
	addedDefinitions := differenceKeys(definitions, frozen.ContractDefinitions)
	expectedDefinitions, err := addedCommandDefinitionClosure(commands, definitions, frozen.ContractDefinitions, []string{"next", "status"})
	if err != nil {
		return err
	}
	if !slices.Equal(addedDefinitions, expectedDefinitions) {
		return fmt.Errorf("current CLI definition additions are not exactly closed by added commands: got %v want %v", addedDefinitions, expectedDefinitions)
	}

	process, ok := current["processContract"].(map[string]any)
	if !ok {
		return fmt.Errorf("current CLI process contract is invalid")
	}
	normalizedProcess := clonePublicABIRecord(process)
	grammar, ok := process["commandRouteGrammar"].(map[string]any)
	if !ok {
		return fmt.Errorf("current CLI command route grammar is invalid")
	}
	normalizedGrammar := clonePublicABIRecord(grammar)
	if normalizedGrammar["omittedRoutePolicy"] != "command_id" {
		return fmt.Errorf("current CLI omitted route policy is invalid")
	}
	delete(normalizedGrammar, "omittedRoutePolicy")
	normalizedProcess["commandRouteGrammar"] = normalizedGrammar
	processDigest, err := digest.StableJSONSHA256Ref(normalizedProcess)
	if err != nil {
		return fmt.Errorf("fingerprint normalized process contract: %w", err)
	}
	if processDigest != frozen.ProcessContractSHA256 {
		return fmt.Errorf("current CLI process contract has undeclared ABI drift")
	}
	return nil
}
