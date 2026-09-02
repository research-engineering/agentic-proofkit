package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const agentRouteVersionEdgePath = "internal/app/testdata/v0.6-wire-observations.json"

type agentRouteVersionEdge struct {
	ChangedCommandContract  agentRouteChangedCommandContract `json:"changedCommandContract"`
	ChangeRecordRef         string                           `json:"changeRecordRef"`
	ChangeRecordSHA256      string                           `json:"changeRecordSha256"`
	CurrentPublicABISHA256  string                           `json:"currentPublicAbiSha256"`
	EdgeID                  string                           `json:"edgeId"`
	EvidenceClass           string                           `json:"evidenceClass"`
	NonClaims               []string                         `json:"nonClaims"`
	PreviousPublicABISHA256 string                           `json:"previousPublicAbiSha256"`
	PreviousVersion         string                           `json:"previousVersion"`
	SchemaVersion           int                              `json:"schemaVersion"`
	Version                 string                           `json:"version"`
}

type agentRouteChangedCommandContract struct {
	Command                      string `json:"command"`
	CurrentInputContractSHA256   string `json:"currentInputContractSha256"`
	CurrentOutputContractSHA256  string `json:"currentOutputContractSha256"`
	PreviousInputContractSHA256  string `json:"previousInputContractSha256"`
	PreviousOutputContractSHA256 string `json:"previousOutputContractSha256"`
}

func TestAgentRouteVersionEdgeClosesBriefDefaultMigration(t *testing.T) {
	record := readAgentRouteVersionEdge(t)
	root := repoRoot(t)
	if err := validateAgentRouteVersionEdge(record, root); err != nil {
		t.Fatal(err)
	}

	mutants := []struct {
		name   string
		mutate func(*agentRouteVersionEdge)
	}{
		{name: "current ABI", mutate: func(value *agentRouteVersionEdge) { value.CurrentPublicABISHA256 += "0" }},
		{name: "previous ABI", mutate: func(value *agentRouteVersionEdge) { value.PreviousPublicABISHA256 = value.CurrentPublicABISHA256 }},
		{name: "command", mutate: func(value *agentRouteVersionEdge) { value.ChangedCommandContract.Command = "help" }},
		{name: "current input contract", mutate: func(value *agentRouteVersionEdge) { value.ChangedCommandContract.CurrentInputContractSHA256 += "0" }},
		{name: "current output contract", mutate: func(value *agentRouteVersionEdge) { value.ChangedCommandContract.CurrentOutputContractSHA256 += "0" }},
		{name: "previous input contract", mutate: func(value *agentRouteVersionEdge) { value.ChangedCommandContract.PreviousInputContractSHA256 += "0" }},
		{name: "previous output contract", mutate: func(value *agentRouteVersionEdge) { value.ChangedCommandContract.PreviousOutputContractSHA256 += "0" }},
		{name: "change record reference", mutate: func(value *agentRouteVersionEdge) { value.ChangeRecordRef += ".drift" }},
		{name: "change record digest", mutate: func(value *agentRouteVersionEdge) { value.ChangeRecordSHA256 += "0" }},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			value := cloneAgentRouteVersionEdge(record)
			mutant.mutate(&value)
			if err := validateAgentRouteVersionEdge(value, root); err == nil {
				t.Fatal("version-edge mutant was admitted")
			}
		})
	}
}

func readAgentRouteVersionEdge(t *testing.T) agentRouteVersionEdge {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), agentRouteVersionEdgePath))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("agent-route version edge must be an object")
	}
	assertExactObjectKeys(t, root, []string{"changedCommandContract", "changeRecordRef", "changeRecordSha256", "currentPublicAbiSha256", "edgeId", "evidenceClass", "nonClaims", "previousPublicAbiSha256", "previousVersion", "schemaVersion", "version"}, "agent-route version edge")
	contract, ok := root["changedCommandContract"].(map[string]any)
	if !ok {
		t.Fatal("agent-route version edge changedCommandContract must be an object")
	}
	assertExactObjectKeys(t, contract, []string{"command", "currentInputContractSha256", "currentOutputContractSha256", "previousInputContractSha256", "previousOutputContractSha256"}, "agent-route changed command contract")
	var decoded agentRouteVersionEdge
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func validateAgentRouteVersionEdge(record agentRouteVersionEdge, root string) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.5.1-to-0.6.0" || record.EvidenceClass != "owner_authored_frozen_version_edge_observation" {
		return fmt.Errorf("agent-route version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.5.1" || record.Version != "0.6.0" {
		return fmt.Errorf("agent-route version-edge release identity is stale")
	}
	if record.PreviousPublicABISHA256 != "sha256:9ecd2c3d2f3f360088409f7e91cce406fc1d1d6edda1b404fce119985c4fb623" || record.CurrentPublicABISHA256 != "sha256:"+cliContractPublicABISHA256 || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("agent-route version-edge ABI identity is invalid")
	}
	currentMetadata, ok := generatedCommandContractMetadataByName["agent-route"]
	if !ok {
		return fmt.Errorf("agent-route version-edge current command metadata is missing")
	}
	wantContract := agentRouteChangedCommandContract{
		Command:                      "agent-route",
		PreviousInputContractSHA256:  "sha256:6b5af8287f2972bbef4c68c247f43fb16d0f0d8739e5e6d3a66543af20d2644d",
		CurrentInputContractSHA256:   currentMetadata.InputContractSHA256,
		PreviousOutputContractSHA256: "sha256:44ec313a43360b6138ad6c3ae5de4abd51bbf312060880c108a6351606695915",
		CurrentOutputContractSHA256:  currentMetadata.OutputContractSHA256,
	}
	if record.ChangedCommandContract != wantContract {
		return fmt.Errorf("agent-route version-edge changed command contract is not exact")
	}
	if record.ChangeRecordRef != "release/change-record.v2.json" {
		return fmt.Errorf("agent-route version-edge change record reference is not exact")
	}
	changeRecordPath := filepath.Join(root, filepath.FromSlash(record.ChangeRecordRef))
	changeRecordContent, err := os.ReadFile(changeRecordPath)
	if err != nil {
		return fmt.Errorf("read agent-route version-edge change record: %w", err)
	}
	changeRecordDigest := sha256.Sum256(changeRecordContent)
	if record.ChangeRecordSHA256 != fmt.Sprintf("sha256:%x", changeRecordDigest) {
		return fmt.Errorf("agent-route version-edge change record digest is not exact")
	}
	changeRecord, err := releasechange.Read(changeRecordPath)
	if err != nil {
		return fmt.Errorf("admit agent-route version-edge change record: %w", err)
	}
	if changeRecord.PreviousVersion != record.PreviousVersion || changeRecord.Version != record.Version || !changeRecord.Migration.Required {
		return fmt.Errorf("agent-route version-edge change record identity is inconsistent")
	}
	if !slices.Equal(record.NonClaims, []string{"This owner-authored version-edge observation binds reviewed public contract identities; it does not authenticate Git history, registry publication, provider ingestion, native witness truth, rollout, or production readiness."}) {
		return fmt.Errorf("agent-route version-edge non-claims are not exact")
	}
	return nil
}

func cloneAgentRouteVersionEdge(record agentRouteVersionEdge) agentRouteVersionEdge {
	record.NonClaims = append([]string(nil), record.NonClaims...)
	return record
}
