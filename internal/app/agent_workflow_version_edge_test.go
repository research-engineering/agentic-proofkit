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

const agentWorkflowVersionEdgePath = "internal/app/testdata/v0.5-wire-observations.json"

type agentWorkflowVersionEdge struct {
	AddedCommandContracts         []agentWorkflowCommandContract `json:"addedCommandContracts"`
	AdditionChangeIDs             []string                       `json:"additionChangeIds"`
	BreakingChangeIDs             []string                       `json:"breakingChangeIds"`
	CurrentPublicABISHA256        string                         `json:"currentPublicAbiSha256"`
	CurrentTypeScriptGeneratorID  string                         `json:"currentTypeScriptGeneratorId"`
	EdgeID                        string                         `json:"edgeId"`
	EvidenceClass                 string                         `json:"evidenceClass"`
	NonClaims                     []string                       `json:"nonClaims"`
	PreviousPublicABISHA256       string                         `json:"previousPublicAbiSha256"`
	PreviousTypeScriptGeneratorID string                         `json:"previousTypeScriptGeneratorId"`
	PreviousVersion               string                         `json:"previousVersion"`
	SchemaVersion                 int                            `json:"schemaVersion"`
	Version                       string                         `json:"version"`
}

type agentWorkflowCommandContract struct {
	Command              string `json:"command"`
	InputContractSHA256  string `json:"inputContractSha256"`
	OutputContractSHA256 string `json:"outputContractSha256"`
}

func TestAgentWorkflowVersionEdgeClosesPublicWireAdditions(t *testing.T) {
	record := readAgentWorkflowVersionEdge(t)
	if err := validateAgentWorkflowVersionEdge(record); err != nil {
		t.Fatal(err)
	}

	mutants := []struct {
		name   string
		mutate func(*agentWorkflowVersionEdge)
	}{
		{name: "current ABI", mutate: func(value *agentWorkflowVersionEdge) { value.CurrentPublicABISHA256 += "0" }},
		{name: "previous ABI", mutate: func(value *agentWorkflowVersionEdge) { value.PreviousPublicABISHA256 = value.CurrentPublicABISHA256 }},
		{name: "current TypeScript generator", mutate: func(value *agentWorkflowVersionEdge) { value.CurrentTypeScriptGeneratorID += ".drift" }},
		{name: "previous TypeScript generator", mutate: func(value *agentWorkflowVersionEdge) {
			value.PreviousTypeScriptGeneratorID = value.CurrentTypeScriptGeneratorID
		}},
		{name: "command contract", mutate: func(value *agentWorkflowVersionEdge) { value.AddedCommandContracts[0].OutputContractSHA256 += "0" }},
		{name: "missing command", mutate: func(value *agentWorkflowVersionEdge) { value.AddedCommandContracts = value.AddedCommandContracts[1:] }},
		{name: "addition owner", mutate: func(value *agentWorkflowVersionEdge) { value.AdditionChangeIDs[0] += ".drift" }},
		{name: "missing addition", mutate: func(value *agentWorkflowVersionEdge) { value.AdditionChangeIDs = value.AdditionChangeIDs[1:] }},
		{name: "reordered additions", mutate: func(value *agentWorkflowVersionEdge) {
			value.AdditionChangeIDs[0], value.AdditionChangeIDs[1] = value.AdditionChangeIDs[1], value.AdditionChangeIDs[0]
		}},
		{name: "surplus addition", mutate: func(value *agentWorkflowVersionEdge) {
			value.AdditionChangeIDs = append(value.AdditionChangeIDs, "proofkit.surplus")
		}},
		{name: "breaking owner", mutate: func(value *agentWorkflowVersionEdge) { value.BreakingChangeIDs[0] += ".drift" }},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			value := cloneAgentWorkflowVersionEdge(record)
			mutant.mutate(&value)
			if err := validateAgentWorkflowVersionEdge(value); err == nil {
				t.Fatal("version-edge mutant was admitted")
			}
		})
	}
}

func readAgentWorkflowVersionEdge(t *testing.T) agentWorkflowVersionEdge {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), agentWorkflowVersionEdgePath))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("agent workflow version edge must be an object")
	}
	assertExactObjectKeys(t, root, []string{"addedCommandContracts", "additionChangeIds", "breakingChangeIds", "currentPublicAbiSha256", "currentTypeScriptGeneratorId", "edgeId", "evidenceClass", "nonClaims", "previousPublicAbiSha256", "previousTypeScriptGeneratorId", "previousVersion", "schemaVersion", "version"}, "agent workflow version edge")
	commandContracts, ok := root["addedCommandContracts"].([]any)
	if !ok {
		t.Fatal("agent workflow version edge addedCommandContracts must be an array")
	}
	for index, raw := range commandContracts {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("added command contract %d must be an object", index)
		}
		assertExactObjectKeys(t, item, []string{"command", "inputContractSha256", "outputContractSha256"}, fmt.Sprintf("added command contract %d", index))
	}
	var decoded agentWorkflowVersionEdge
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func validateAgentWorkflowVersionEdge(record agentWorkflowVersionEdge) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.4.0-to-0.5.0" || record.EvidenceClass != "owner_authored_frozen_version_edge_observation" {
		return fmt.Errorf("version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.4.0" || record.Version != "0.5.0" {
		return fmt.Errorf("version-edge release identity is stale")
	}
	if record.PreviousPublicABISHA256 != "sha256:fc03740aea9e7f525a4388e5d7f557cde07e11b0db0c05101fe937c28a1129d9" || record.CurrentPublicABISHA256 != "sha256:9ecd2c3d2f3f360088409f7e91cce406fc1d1d6edda1b404fce119985c4fb623" || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("version-edge ABI identity is invalid")
	}
	if record.PreviousTypeScriptGeneratorID != "proofkit.json-report-cli-adapter-source.typescript.v1" || record.CurrentTypeScriptGeneratorID != "proofkit.json-report-cli-adapter-source.typescript.v2" || record.PreviousTypeScriptGeneratorID == record.CurrentTypeScriptGeneratorID {
		return fmt.Errorf("version-edge TypeScript generator identity is invalid")
	}
	expectedCommands := []agentWorkflowCommandContract{
		{Command: "change-workflow-plan", InputContractSHA256: "sha256:e3124fc636b7f66b24daf8e1435cea11da15a741abeabe0cc3d3890b13c71625", OutputContractSHA256: "sha256:cd035e9b71d83c341b1a937a18699fd727cb4b0d694983d715b064292ae4d8bd"},
		{Command: "native-evidence-guidance", InputContractSHA256: "", OutputContractSHA256: "sha256:c1d23df574e948ea7160931f53790a6d133ae12eeceefe9e5fa15430d653ff7e"},
	}
	if !slices.Equal(record.AddedCommandContracts, expectedCommands) {
		return fmt.Errorf("version-edge added command contracts are not exact")
	}
	expectedAdditions := []string{"proofkit.agent-workflow.change-planner", "proofkit.agent-workflow.native-evidence-guidance", "proofkit.release.cross-carrier-binary-identity"}
	if !slices.Equal(record.AdditionChangeIDs, expectedAdditions) {
		return fmt.Errorf("version-edge addition owners are not exact")
	}
	expectedBreaking := []string{"proofkit.agent-envelope.local-identity-closure", "proofkit.diagnostic.bounded-error-boundary", "proofkit.stable-json.unicode-scalar-v2"}
	if !slices.Equal(record.BreakingChangeIDs, expectedBreaking) {
		return fmt.Errorf("version-edge breaking change owners are not exact")
	}
	if !slices.Equal(record.NonClaims, []string{"This owner-authored version-edge observation binds reviewed public contract identities; it does not authenticate Git history, registry publication, provider ingestion, native witness truth, rollout, or production readiness."}) {
		return fmt.Errorf("version-edge non-claims are not exact")
	}
	return nil
}

func cloneAgentWorkflowVersionEdge(record agentWorkflowVersionEdge) agentWorkflowVersionEdge {
	record.AddedCommandContracts = append([]agentWorkflowCommandContract(nil), record.AddedCommandContracts...)
	record.AdditionChangeIDs = append([]string(nil), record.AdditionChangeIDs...)
	record.BreakingChangeIDs = append([]string(nil), record.BreakingChangeIDs...)
	record.NonClaims = append([]string(nil), record.NonClaims...)
	return record
}
