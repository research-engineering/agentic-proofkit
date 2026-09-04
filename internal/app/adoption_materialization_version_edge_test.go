package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const adoptionMaterializationVersionEdgePath = "internal/app/testdata/v0.8-wire-observations.json"

type adoptionMaterializationVersionEdge struct {
	AddedCommandContracts    []materializationCommandContract `json:"addedCommandContracts"`
	AdditionChangeIDs        []string                         `json:"additionChangeIds"`
	BreakingChangeIDs        []string                         `json:"breakingChangeIds"`
	ChangeClass              string                           `json:"changeClass"`
	ChangeRecordRef          string                           `json:"changeRecordRef"`
	ChangeRecordSHA256       string                           `json:"changeRecordSha256"`
	CommandContractSelection string                           `json:"commandContractSelection"`
	CurrentPublicABISHA256   string                           `json:"currentPublicAbiSha256"`
	EdgeID                   string                           `json:"edgeId"`
	EvidenceClass            string                           `json:"evidenceClass"`
	NonClaims                []string                         `json:"nonClaims"`
	PreviousPublicABISHA256  string                           `json:"previousPublicAbiSha256"`
	PreviousVersion          string                           `json:"previousVersion"`
	SchemaVersion            int                              `json:"schemaVersion"`
	Version                  string                           `json:"version"`
}

type materializationCommandContract struct {
	Command        string                       `json:"command"`
	InputContract  *versionEdgeContractIdentity `json:"inputContract,omitempty"`
	OutputContract versionEdgeContractIdentity  `json:"outputContract"`
	Route          []string                     `json:"route"`
}

type versionEdgeContractIdentity struct {
	ContractID     string `json:"contractId"`
	ContractSHA256 string `json:"contractSha256"`
}

func TestAdoptionMaterializationVersionEdgeClosesPublicCommands(t *testing.T) {
	record := readAdoptionMaterializationVersionEdge(t)
	currentABI := "sha256:" + currentCLIContractPublicABISHA256(t)
	currentCommands, err := currentMaterializationCommandContracts(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAdoptionMaterializationVersionEdge(record, repoRoot(t), currentABI, currentCommands); err != nil {
		t.Fatal(err)
	}

	mutants := []func(*adoptionMaterializationVersionEdge){
		func(value *adoptionMaterializationVersionEdge) { value.CurrentPublicABISHA256 += "0" },
		func(value *adoptionMaterializationVersionEdge) {
			value.PreviousPublicABISHA256 = value.CurrentPublicABISHA256
		},
		func(value *adoptionMaterializationVersionEdge) {
			value.AddedCommandContracts = value.AddedCommandContracts[1:]
		},
		func(value *adoptionMaterializationVersionEdge) {
			value.AddedCommandContracts[0].Route = []string{"adopt-materialize-apply"}
		},
		func(value *adoptionMaterializationVersionEdge) {
			value.AddedCommandContracts[0].InputContract.ContractID += ".drift"
		},
		func(value *adoptionMaterializationVersionEdge) {
			value.AddedCommandContracts[1].OutputContract.ContractSHA256 += "0"
		},
		func(value *adoptionMaterializationVersionEdge) {
			value.AddedCommandContracts[2].InputContract = &versionEdgeContractIdentity{}
		},
		func(value *adoptionMaterializationVersionEdge) { value.AdditionChangeIDs = value.AdditionChangeIDs[1:] },
		func(value *adoptionMaterializationVersionEdge) {
			value.BreakingChangeIDs = []string{"proofkit.unreported.breaking-change"}
		},
		func(value *adoptionMaterializationVersionEdge) { value.ChangeRecordSHA256 += "0" },
		func(value *adoptionMaterializationVersionEdge) { value.CommandContractSelection = "all_digest_changes" },
		func(value *adoptionMaterializationVersionEdge) { value.NonClaims = nil },
	}
	for index, mutate := range mutants {
		t.Run(fmt.Sprintf("mutant-%d", index), func(t *testing.T) {
			value := cloneAdoptionMaterializationVersionEdge(record)
			mutate(&value)
			if err := validateAdoptionMaterializationVersionEdge(value, repoRoot(t), currentABI, currentCommands); err == nil {
				t.Fatal("materialization version-edge mutant was admitted")
			}
		})
	}
}

func TestAdoptionMaterializationVersionEdgeRejectsCoordinatedChangeRecordDrift(t *testing.T) {
	record := readAdoptionMaterializationVersionEdge(t)
	currentABI := "sha256:" + currentCLIContractPublicABISHA256(t)
	currentCommands, err := currentMaterializationCommandContracts(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(repoRoot(t), record.ChangeRecordRef))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root := value.(map[string]any)
	root["additions"].([]any)[0].(map[string]any)["changeId"] = "proofkit.adoption.transactional-materialization.drift"
	mutantContent, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mutantContent = append(mutantContent, '\n')
	mutantRoot := t.TempDir()
	path := filepath.Join(mutantRoot, filepath.FromSlash(record.ChangeRecordRef))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mutantContent, 0o600); err != nil {
		t.Fatal(err)
	}
	mutant := cloneAdoptionMaterializationVersionEdge(record)
	digest := sha256.Sum256(mutantContent)
	mutant.ChangeRecordSHA256 = fmt.Sprintf("sha256:%x", digest)
	if err := validateAdoptionMaterializationVersionEdge(mutant, mutantRoot, currentABI, currentCommands); err == nil || !strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("coordinated change-record mutant error=%v, want inventory contradiction", err)
	}
}

func readAdoptionMaterializationVersionEdge(t *testing.T) adoptionMaterializationVersionEdge {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), adoptionMaterializationVersionEdgePath))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("adoption materialization version edge must be an object")
	}
	assertExactObjectKeys(t, root, []string{"addedCommandContracts", "additionChangeIds", "breakingChangeIds", "changeClass", "changeRecordRef", "changeRecordSha256", "commandContractSelection", "currentPublicAbiSha256", "edgeId", "evidenceClass", "nonClaims", "previousPublicAbiSha256", "previousVersion", "schemaVersion", "version"}, "adoption materialization version edge")
	added, ok := root["addedCommandContracts"].([]any)
	if !ok {
		t.Fatal("added command contracts must be an array")
	}
	for index, raw := range added {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("added command contract %d must be an object", index)
		}
		keys := []string{"command", "outputContract", "route"}
		if _, hasInput := item["inputContract"]; hasInput {
			keys = append(keys, "inputContract")
			slices.Sort(keys)
		}
		assertExactObjectKeys(t, item, keys, fmt.Sprintf("added command contract %d", index))
		for _, field := range []string{"inputContract", "outputContract"} {
			identity, present := item[field]
			if !present {
				continue
			}
			record, ok := identity.(map[string]any)
			if !ok {
				t.Fatalf("added command contract %d %s must be an object", index, field)
			}
			assertExactObjectKeys(t, record, []string{"contractId", "contractSha256"}, fmt.Sprintf("added command contract %d %s", index, field))
		}
	}
	var record adoptionMaterializationVersionEdge
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func validateAdoptionMaterializationVersionEdge(record adoptionMaterializationVersionEdge, changeRecordRoot, currentPublicABI string, currentCommands []materializationCommandContract) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.7.0-to-0.8.0" || record.EvidenceClass != "owner_authored_current_version_edge_observation" {
		return fmt.Errorf("adoption materialization version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.7.0" || record.Version != "0.8.0" || record.ChangeClass != "compatible" {
		return fmt.Errorf("adoption materialization version-edge release identity is invalid")
	}
	if record.CommandContractSelection != "added_public_commands" {
		return fmt.Errorf("adoption materialization command-contract selection policy is invalid")
	}
	if record.PreviousPublicABISHA256 != "sha256:c3b7219fccd7d400b182beb53715f69758e02a4fef6f9465ba0c80a866abd1c7" || record.CurrentPublicABISHA256 != currentPublicABI || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("adoption materialization version-edge ABI identity is invalid: previous=%s current=%s wantCurrent=%s", record.PreviousPublicABISHA256, record.CurrentPublicABISHA256, currentPublicABI)
	}
	if !slices.EqualFunc(record.AddedCommandContracts, currentCommands, equalMaterializationCommandContract) {
		return fmt.Errorf("adoption materialization added command contracts are not exact")
	}
	if !slices.Equal(record.BreakingChangeIDs, []string{}) || !slices.Equal(record.AdditionChangeIDs, []string{"proofkit.adoption.transactional-materialization", "proofkit.repository.transaction-protocol"}) {
		return fmt.Errorf("adoption materialization change inventory is not exact")
	}
	if record.ChangeRecordRef != releasechange.RecordPath {
		return fmt.Errorf("adoption materialization change record reference is not exact")
	}
	changeRecordPath := filepath.Join(changeRecordRoot, filepath.FromSlash(record.ChangeRecordRef))
	changeRecordContent, err := os.ReadFile(changeRecordPath)
	if err != nil {
		return fmt.Errorf("read adoption materialization change record: %w", err)
	}
	digest := sha256.Sum256(changeRecordContent)
	if record.ChangeRecordSHA256 != fmt.Sprintf("sha256:%x", digest) {
		return fmt.Errorf("adoption materialization change record digest is not exact")
	}
	changeRecord, err := releasechange.Read(changeRecordPath)
	if err != nil {
		return fmt.Errorf("admit adoption materialization change record: %w", err)
	}
	if changeRecord.PreviousVersion != record.PreviousVersion || changeRecord.Version != record.Version || changeRecord.ChangeClass != record.ChangeClass || changeRecord.Migration.Required || len(changeRecord.Migration.Steps) != 0 {
		return fmt.Errorf("adoption materialization change record identity is inconsistent")
	}
	if !slices.Equal(record.BreakingChangeIDs, releaseChangeIDs(changeRecord.BreakingChanges)) || !slices.Equal(record.AdditionChangeIDs, releaseChangeIDs(changeRecord.Additions)) {
		return fmt.Errorf("adoption materialization change inventory contradicts the bound change record")
	}
	if !slices.Equal(record.NonClaims, []string{"This owner-authored version-edge observation binds source and contract identities; it does not authenticate registry publication, provider ingestion, consumer adoption, native witness truth, rollout, or production readiness."}) {
		return fmt.Errorf("adoption materialization version-edge non-claims are not exact")
	}
	return nil
}

func currentMaterializationCommandContracts(root string) ([]materializationCommandContract, error) {
	content, err := os.ReadFile(filepath.Join(root, "proofkit", "cli-contract.v2.json"))
	if err != nil {
		return nil, fmt.Errorf("read current CLI contract: %w", err)
	}
	contract, err := admission.DecodeTypedJSON[cliContract](bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("admit current CLI contract: %w", err)
	}
	result := make([]materializationCommandContract, 0, 3)
	for _, name := range []string{"adopt-materialize-apply", "adopt-materialize-plan", "adopt-materialize-recover"} {
		var command *cliContractCommand
		for index := range contract.Commands {
			if contract.Commands[index].Command == name {
				command = &contract.Commands[index]
				break
			}
		}
		if command == nil {
			return nil, fmt.Errorf("current CLI contract is missing %s", name)
		}
		metadata := generatedCommandContractMetadataByName[name]
		if metadata.OutputContractSHA256 == "" || (command.InputContract != nil && metadata.InputContractSHA256 == "") {
			return nil, fmt.Errorf("generated command contract metadata is incomplete for %s", name)
		}
		item := materializationCommandContract{
			Command: name,
			OutputContract: versionEdgeContractIdentity{
				ContractID:     contractIDFromRaw(command.OutputContract),
				ContractSHA256: metadata.OutputContractSHA256,
			},
			Route: effectiveContractRoute(*command),
		}
		if command.InputContract != nil {
			item.InputContract = &versionEdgeContractIdentity{
				ContractID:     contractIDFromRaw(command.InputContract),
				ContractSHA256: metadata.InputContractSHA256,
			}
		}
		result = append(result, item)
	}
	return result, nil
}

func contractIDFromRaw(raw any) string {
	record, _ := raw.(map[string]any)
	contractID, _ := record["contractId"].(string)
	return contractID
}

func equalMaterializationCommandContract(left, right materializationCommandContract) bool {
	return left.Command == right.Command && slices.Equal(left.Route, right.Route) && equalOptionalContractIdentity(left.InputContract, right.InputContract) && left.OutputContract == right.OutputContract
}

func equalOptionalContractIdentity(left, right *versionEdgeContractIdentity) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func cloneAdoptionMaterializationVersionEdge(record adoptionMaterializationVersionEdge) adoptionMaterializationVersionEdge {
	record.AddedCommandContracts = append([]materializationCommandContract(nil), record.AddedCommandContracts...)
	for index := range record.AddedCommandContracts {
		record.AddedCommandContracts[index].Route = append([]string(nil), record.AddedCommandContracts[index].Route...)
		if record.AddedCommandContracts[index].InputContract != nil {
			value := *record.AddedCommandContracts[index].InputContract
			record.AddedCommandContracts[index].InputContract = &value
		}
	}
	record.AdditionChangeIDs = append([]string(nil), record.AdditionChangeIDs...)
	record.BreakingChangeIDs = append([]string(nil), record.BreakingChangeIDs...)
	record.NonClaims = append([]string(nil), record.NonClaims...)
	return record
}
