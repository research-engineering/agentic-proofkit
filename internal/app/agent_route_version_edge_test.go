package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

const agentRouteVersionEdgePath = "internal/app/testdata/v0.6-wire-observations.json"

type agentRouteVersionEdge struct {
	AdditionChangeIDs       []string                         `json:"additionChangeIds"`
	BreakingChangeIDs       []string                         `json:"breakingChangeIds"`
	ChangedCommandContract  agentRouteChangedCommandContract `json:"changedCommandContract"`
	CurrentPublicABISHA256  string                           `json:"currentPublicAbiSha256"`
	EdgeID                  string                           `json:"edgeId"`
	EvidenceClass           string                           `json:"evidenceClass"`
	MigrationSteps          []string                         `json:"migrationSteps"`
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
	if err := validateAgentRouteVersionEdge(record); err != nil {
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
		{name: "breaking owner", mutate: func(value *agentRouteVersionEdge) { value.BreakingChangeIDs[0] += ".drift" }},
		{name: "missing breaking owner", mutate: func(value *agentRouteVersionEdge) { value.BreakingChangeIDs = value.BreakingChangeIDs[:1] }},
		{name: "addition owner", mutate: func(value *agentRouteVersionEdge) { value.AdditionChangeIDs[0] += ".drift" }},
		{name: "migration", mutate: func(value *agentRouteVersionEdge) { value.MigrationSteps[0] += " Drift." }},
		{name: "missing migration", mutate: func(value *agentRouteVersionEdge) { value.MigrationSteps = value.MigrationSteps[:1] }},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			value := cloneAgentRouteVersionEdge(record)
			mutant.mutate(&value)
			if err := validateAgentRouteVersionEdge(value); err == nil {
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
	assertExactObjectKeys(t, root, []string{"additionChangeIds", "breakingChangeIds", "changedCommandContract", "currentPublicAbiSha256", "edgeId", "evidenceClass", "migrationSteps", "nonClaims", "previousPublicAbiSha256", "previousVersion", "schemaVersion", "version"}, "agent-route version edge")
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

func validateAgentRouteVersionEdge(record agentRouteVersionEdge) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.5.1-to-0.6.0" || record.EvidenceClass != "owner_authored_frozen_version_edge_observation" {
		return fmt.Errorf("agent-route version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.5.1" || record.Version != "0.6.0" {
		return fmt.Errorf("agent-route version-edge release identity is stale")
	}
	if record.PreviousPublicABISHA256 != "sha256:9ecd2c3d2f3f360088409f7e91cce406fc1d1d6edda1b404fce119985c4fb623" || record.CurrentPublicABISHA256 != "sha256:3dc6dead6d21c6a463426594c2e10e2b9dceffd0d16a08ed0fb9ebe2e679e0c0" || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("agent-route version-edge ABI identity is invalid")
	}
	wantContract := agentRouteChangedCommandContract{
		Command:                      "agent-route",
		PreviousInputContractSHA256:  "sha256:6b5af8287f2972bbef4c68c247f43fb16d0f0d8739e5e6d3a66543af20d2644d",
		CurrentInputContractSHA256:   "sha256:60bafcd877e0bd26bb9fbd37343ba7e19d61d314afbd7062754c8574ffd36c41",
		PreviousOutputContractSHA256: "sha256:44ec313a43360b6138ad6c3ae5de4abd51bbf312060880c108a6351606695915",
		CurrentOutputContractSHA256:  "sha256:e160ea2e5531b6675f7c4edfb01a2fb0d32fd7c74189e9c38774c41a211dc29e",
	}
	if record.ChangedCommandContract != wantContract {
		return fmt.Errorf("agent-route version-edge changed command contract is not exact")
	}
	if !slices.Equal(record.BreakingChangeIDs, []string{"proofkit.agent-route.brief-default", "proofkit.agent-route.materialized-artifact-refs"}) || !slices.Equal(record.AdditionChangeIDs, []string{"proofkit.agent-route.envelope-detail-mode"}) {
		return fmt.Errorf("agent-route version-edge change owners are not exact")
	}
	if !slices.Equal(record.MigrationSteps, []string{
		"Consumers that require the former generic agent-route envelope must add --agent-envelope-mode full after --agent-envelope; consumers that accept bounded route guidance may keep bare --agent-envelope.",
		"Consumers that used the stdin transport sentinel as an agent-route availableInputs or observedReports ref must materialize that artifact and pass its safe repo-relative path instead.",
	}) {
		return fmt.Errorf("agent-route version-edge migration is not exact")
	}
	if !slices.Equal(record.NonClaims, []string{"This owner-authored version-edge observation binds reviewed public contract identities; it does not authenticate Git history, registry publication, provider ingestion, native witness truth, rollout, or production readiness."}) {
		return fmt.Errorf("agent-route version-edge non-claims are not exact")
	}
	return nil
}

func cloneAgentRouteVersionEdge(record agentRouteVersionEdge) agentRouteVersionEdge {
	record.AdditionChangeIDs = append([]string(nil), record.AdditionChangeIDs...)
	record.BreakingChangeIDs = append([]string(nil), record.BreakingChangeIDs...)
	record.MigrationSteps = append([]string(nil), record.MigrationSteps...)
	record.NonClaims = append([]string(nil), record.NonClaims...)
	return record
}
