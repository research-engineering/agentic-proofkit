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
const archivedAdoptionMaterializationReleaseRoot = "internal/app/testdata/releases/v0.8.0"

const frozenAdoptionFrontDoorVersionEdgePath = "internal/app/testdata/v0.7-wire-observations.json"
const frozenAdoptionFrontDoorVersionEdgeSHA256 = "3f3916ff3413aed42539cfd122d0796b636f6819512459a13f4143443bd2a14e"

type adoptionMaterializationVersionEdge struct {
	AddedCommandContracts    []versionEdgeCommandContract `json:"addedCommandContracts"`
	AdditionChangeIDs        []string                     `json:"additionChangeIds"`
	BreakingChangeIDs        []string                     `json:"breakingChangeIds"`
	ChangeClass              string                       `json:"changeClass"`
	ChangeRecordRef          string                       `json:"changeRecordRef"`
	ChangeRecordSHA256       string                       `json:"changeRecordSha256"`
	CommandContractSelection string                       `json:"commandContractSelection"`
	CurrentPublicABISHA256   string                       `json:"currentPublicAbiSha256"`
	EdgeID                   string                       `json:"edgeId"`
	EvidenceClass            string                       `json:"evidenceClass"`
	NonClaims                []string                     `json:"nonClaims"`
	PreviousPublicABISHA256  string                       `json:"previousPublicAbiSha256"`
	PreviousVersion          string                       `json:"previousVersion"`
	SchemaVersion            int                          `json:"schemaVersion"`
	Version                  string                       `json:"version"`
}

type versionEdgeCommandContract struct {
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
	if err := validateAdoptionMaterializationVersionEdge(record, archivedAdoptionMaterializationRoot(t)); err != nil {
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
			if err := validateAdoptionMaterializationVersionEdge(value, archivedAdoptionMaterializationRoot(t)); err == nil {
				t.Fatal("materialization version-edge mutant was admitted")
			}
		})
	}
}

func TestAdoptionMaterializationVersionEdgePreservesFrozenPredecessor(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot(t), frozenAdoptionFrontDoorVersionEdgePath))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if got := fmt.Sprintf("%x", digest); got != frozenAdoptionFrontDoorVersionEdgeSHA256 {
		t.Fatalf("frozen predecessor digest=%s, want %s", got, frozenAdoptionFrontDoorVersionEdgeSHA256)
	}
}

func TestAdoptionMaterializationVersionEdgeRejectsCoordinatedChangeRecordDrift(t *testing.T) {
	record := readAdoptionMaterializationVersionEdge(t)
	content, err := os.ReadFile(filepath.Join(archivedAdoptionMaterializationRoot(t), record.ChangeRecordRef))
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
	if err := validateAdoptionMaterializationVersionEdge(mutant, mutantRoot); err == nil || !strings.Contains(err.Error(), "contradicts") {
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

func validateAdoptionMaterializationVersionEdge(record adoptionMaterializationVersionEdge, changeRecordRoot string) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.7.0-to-0.8.0" || record.EvidenceClass != "owner_authored_current_version_edge_observation" {
		return fmt.Errorf("adoption materialization version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.7.0" || record.Version != "0.8.0" || record.ChangeClass != "compatible" {
		return fmt.Errorf("adoption materialization version-edge release identity is invalid")
	}
	if record.CommandContractSelection != "added_public_commands" {
		return fmt.Errorf("adoption materialization command-contract selection policy is invalid")
	}
	if record.PreviousPublicABISHA256 != "sha256:c3b7219fccd7d400b182beb53715f69758e02a4fef6f9465ba0c80a866abd1c7" || record.CurrentPublicABISHA256 != "sha256:b5ea707ee5851cea6b75442e4faf20e93879371faf3636e96a98ccd23b527463" || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("adoption materialization version-edge ABI identity is invalid")
	}
	if !slices.EqualFunc(record.AddedCommandContracts, frozenMaterializationCommandContracts(), equalVersionEdgeCommandContract) {
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

func archivedAdoptionMaterializationRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), archivedAdoptionMaterializationReleaseRoot)
}

func frozenMaterializationCommandContracts() []versionEdgeCommandContract {
	return []versionEdgeCommandContract{
		{
			Command: "adopt-materialize-apply", Route: []string{"adopt", "materialize", "apply"},
			InputContract:  &versionEdgeContractIdentity{ContractID: "proofkit.adopt-materialize-apply.input.v1", ContractSHA256: "sha256:073bc4b983038d593e6a655104af51bb2a105974946ef5e2c9b857c68db6577f"},
			OutputContract: versionEdgeContractIdentity{ContractID: "proofkit.adopt-materialize-apply.output.v1", ContractSHA256: "sha256:a3ff3ab6f2835ce6eb6bd69351adec171d722663d7d33aabaeade33e52f411af"},
		},
		{
			Command: "adopt-materialize-plan", Route: []string{"adopt", "materialize", "plan"},
			InputContract:  &versionEdgeContractIdentity{ContractID: "proofkit.adopt-materialize-plan.input.v1", ContractSHA256: "sha256:e7f2b1339f8ab11f577872d409b4fec66c79a79febe8cef7cfd15b969c0c4de4"},
			OutputContract: versionEdgeContractIdentity{ContractID: "proofkit.adopt-materialize-plan.output.v1", ContractSHA256: "sha256:02fc198c3a8eb0d03505f008c27e51c103b7b608eb3870e1757de529f697909a"},
		},
		{
			Command: "adopt-materialize-recover", Route: []string{"adopt", "materialize", "recover"},
			OutputContract: versionEdgeContractIdentity{ContractID: "proofkit.adopt-materialize-recover.output.v1", ContractSHA256: "sha256:a24c3c8710e000e83f068a3d98bc33f0239076687c04d1d72d2457d8a389bef3"},
		},
	}
}

func contractIDFromRaw(raw any) string {
	record, _ := raw.(map[string]any)
	contractID, _ := record["contractId"].(string)
	return contractID
}

func equalVersionEdgeCommandContract(left, right versionEdgeCommandContract) bool {
	return left.Command == right.Command && slices.Equal(left.Route, right.Route) && equalOptionalContractIdentity(left.InputContract, right.InputContract) && left.OutputContract == right.OutputContract
}

func equalOptionalContractIdentity(left, right *versionEdgeContractIdentity) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func cloneAdoptionMaterializationVersionEdge(record adoptionMaterializationVersionEdge) adoptionMaterializationVersionEdge {
	record.AddedCommandContracts = append([]versionEdgeCommandContract(nil), record.AddedCommandContracts...)
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
