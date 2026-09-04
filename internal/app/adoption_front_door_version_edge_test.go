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

	"github.com/research-engineering/agentic-proofkit/internal/command/jsonreportcliadaptersource"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const adoptionFrontDoorVersionEdgePath = "internal/app/testdata/v0.7-wire-observations.json"

type adoptionFrontDoorVersionEdge struct {
	AddedCommandContracts     []adoptionFrontDoorCommandContract `json:"addedCommandContracts"`
	AdditionChangeIDs         []string                           `json:"additionChangeIds"`
	BreakingChangeIDs         []string                           `json:"breakingChangeIds"`
	ChangeRecordRef           string                             `json:"changeRecordRef"`
	ChangeRecordSHA256        string                             `json:"changeRecordSha256"`
	ChangedGeneratedArtifacts []adoptionChangedGeneratedArtifact `json:"changedGeneratedArtifacts"`
	CurrentPublicABISHA256    string                             `json:"currentPublicAbiSha256"`
	EdgeID                    string                             `json:"edgeId"`
	EvidenceClass             string                             `json:"evidenceClass"`
	NonClaims                 []string                           `json:"nonClaims"`
	PreviousPublicABISHA256   string                             `json:"previousPublicAbiSha256"`
	PreviousVersion           string                             `json:"previousVersion"`
	RemovedCommandContract    adoptionRemovedCommandContract     `json:"removedCommandContract"`
	SchemaVersion             int                                `json:"schemaVersion"`
	Version                   string                             `json:"version"`
}

type adoptionFrontDoorCommandContract struct {
	Command              string   `json:"command"`
	OutputContractSHA256 string   `json:"outputContractSha256"`
	Route                []string `json:"route"`
}

type adoptionRemovedCommandContract struct {
	Command                 string `json:"command"`
	DefaultInvocationPreset string `json:"defaultInvocationPreset"`
	OutputContractSHA256    string `json:"outputContractSha256"`
}

type adoptionChangedGeneratedArtifact struct {
	ArtifactKind         string `json:"artifactKind"`
	CurrentSourceSHA256  string `json:"currentSourceSha256"`
	GeneratorID          string `json:"generatorId"`
	PreviousSourceSHA256 string `json:"previousSourceSha256"`
}

func TestAdoptionFrontDoorVersionEdgeClosesInitRetirement(t *testing.T) {
	record := readAdoptionFrontDoorVersionEdge(t)
	currentPublicABI := "sha256:" + currentCLIContractPublicABISHA256(t)
	if err := validateAdoptionFrontDoorVersionEdge(record, repoRoot(t), currentPublicABI); err != nil {
		t.Fatal(err)
	}

	mutants := []func(*adoptionFrontDoorVersionEdge){
		func(value *adoptionFrontDoorVersionEdge) { value.CurrentPublicABISHA256 += "0" },
		func(value *adoptionFrontDoorVersionEdge) {
			value.PreviousPublicABISHA256 = value.CurrentPublicABISHA256
		},
		func(value *adoptionFrontDoorVersionEdge) { value.RemovedCommandContract.Command = "help" },
		func(value *adoptionFrontDoorVersionEdge) {
			value.AddedCommandContracts[0].Route = []string{"adopt-plan"}
		},
		func(value *adoptionFrontDoorVersionEdge) {
			value.AddedCommandContracts = value.AddedCommandContracts[1:]
		},
		func(value *adoptionFrontDoorVersionEdge) { value.BreakingChangeIDs[0] += ".drift" },
		func(value *adoptionFrontDoorVersionEdge) { value.AdditionChangeIDs = value.AdditionChangeIDs[1:] },
		func(value *adoptionFrontDoorVersionEdge) { value.ChangeRecordSHA256 += "0" },
		func(value *adoptionFrontDoorVersionEdge) {
			value.ChangedGeneratedArtifacts[0].PreviousSourceSHA256 = value.ChangedGeneratedArtifacts[0].CurrentSourceSHA256
		},
		func(value *adoptionFrontDoorVersionEdge) {
			value.RemovedCommandContract.DefaultInvocationPreset = "fresh"
		},
	}
	for index, mutate := range mutants {
		t.Run(fmt.Sprintf("mutant-%d", index), func(t *testing.T) {
			value := cloneAdoptionFrontDoorVersionEdge(record)
			mutate(&value)
			if err := validateAdoptionFrontDoorVersionEdge(value, repoRoot(t), currentPublicABI); err == nil {
				t.Fatal("version-edge mutant was admitted")
			}
		})
	}
}

func TestRetiredInitRouteHasNoPublicDispatcher(t *testing.T) {
	status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"init"}, panicReader{}, PresentationCapabilities{})
	if status != 1 || stdout != "" || !strings.Contains(stderr, "unsupported command: init") {
		t.Fatalf("init status/stdout/stderr = %d/%q/%q", status, stdout, stderr)
	}
	if _, ok := commandDescriptorFor("init"); ok {
		t.Fatal("init remains in the command descriptor registry")
	}
}

func readAdoptionFrontDoorVersionEdge(t *testing.T) adoptionFrontDoorVersionEdge {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), adoptionFrontDoorVersionEdgePath))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("adoption front-door version edge must be an object")
	}
	assertExactObjectKeys(t, root, []string{"addedCommandContracts", "additionChangeIds", "breakingChangeIds", "changeRecordRef", "changeRecordSha256", "changedGeneratedArtifacts", "currentPublicAbiSha256", "edgeId", "evidenceClass", "nonClaims", "previousPublicAbiSha256", "previousVersion", "removedCommandContract", "schemaVersion", "version"}, "adoption front-door version edge")
	removed, ok := root["removedCommandContract"].(map[string]any)
	if !ok {
		t.Fatal("removed command contract must be an object")
	}
	assertExactObjectKeys(t, removed, []string{"command", "defaultInvocationPreset", "outputContractSha256"}, "removed command contract")
	added, ok := root["addedCommandContracts"].([]any)
	if !ok {
		t.Fatal("added command contracts must be an array")
	}
	for index, raw := range added {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("added command contract %d must be an object", index)
		}
		assertExactObjectKeys(t, item, []string{"command", "outputContractSha256", "route"}, fmt.Sprintf("added command contract %d", index))
	}
	changedArtifacts, ok := root["changedGeneratedArtifacts"].([]any)
	if !ok {
		t.Fatal("changed generated artifacts must be an array")
	}
	for index, raw := range changedArtifacts {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("changed generated artifact %d must be an object", index)
		}
		assertExactObjectKeys(t, item, []string{"artifactKind", "currentSourceSha256", "generatorId", "previousSourceSha256"}, fmt.Sprintf("changed generated artifact %d", index))
	}
	var record adoptionFrontDoorVersionEdge
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func validateAdoptionFrontDoorVersionEdge(record adoptionFrontDoorVersionEdge, root string, currentPublicABI string) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.6.0-to-0.7.0" || record.EvidenceClass != "owner_authored_frozen_version_edge_observation" {
		return fmt.Errorf("adoption front-door version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.6.0" || record.Version != "0.7.0" {
		return fmt.Errorf("adoption front-door version-edge release identity is stale")
	}
	if record.PreviousPublicABISHA256 != "sha256:163f06bf6fc94f15040fecf3e352d4600a8611a227e26f35369b7fe97e90bde5" || record.CurrentPublicABISHA256 != currentPublicABI || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("adoption front-door version-edge ABI identity is invalid")
	}
	wantRemoved := adoptionRemovedCommandContract{Command: "init", DefaultInvocationPreset: "all", OutputContractSHA256: "sha256:3e59a3002327c759e5e747f8baacaa63a4d6784e1a1c520f0a54e01af3f2faa0"}
	if record.RemovedCommandContract != wantRemoved {
		return fmt.Errorf("adoption front-door removed command contract is not exact")
	}
	wantAdded := []adoptionFrontDoorCommandContract{
		{Command: "adopt-plan", Route: []string{"adopt", "plan"}, OutputContractSHA256: generatedCommandContractMetadataByName["adopt-plan"].OutputContractSHA256},
		{Command: "repository-inventory", Route: []string{"repository-inventory"}, OutputContractSHA256: generatedCommandContractMetadataByName["repository-inventory"].OutputContractSHA256},
	}
	if !slices.EqualFunc(record.AddedCommandContracts, wantAdded, equalAdoptionCommandContract) {
		return fmt.Errorf("adoption front-door added command contracts are not exact")
	}
	wantGeneratedArtifacts := []adoptionChangedGeneratedArtifact{{
		ArtifactKind:         "proofkit.json-report-cli-adapter-source",
		CurrentSourceSHA256:  "sha256:329b88b6b134dc30fb3704d32ac9708fc01608b9df68815bc9585108971be37d",
		GeneratorID:          jsonreportcliadaptersource.TypeScriptGeneratorID,
		PreviousSourceSHA256: "sha256:a171cc1b95c6078b7190ac50fc9fd298db8f42bfc9b65bbb67fa77d63dc04a93",
	}}
	if !slices.Equal(record.ChangedGeneratedArtifacts, wantGeneratedArtifacts) {
		return fmt.Errorf("adoption front-door changed generated artifacts are not exact")
	}
	currentSourceDigest := sha256.Sum256([]byte(jsonreportcliadaptersource.TypeScriptSource()))
	if record.ChangedGeneratedArtifacts[0].CurrentSourceSHA256 != fmt.Sprintf("sha256:%x", currentSourceDigest) {
		return fmt.Errorf("adoption front-door generated adapter source identity is stale")
	}
	if !slices.Equal(record.BreakingChangeIDs, []string{"proofkit.adoption.init-retired"}) || !slices.Equal(record.AdditionChangeIDs, []string{"proofkit.adoption.front-door", "proofkit.adoption.repository-inventory", "proofkit.cli.generated-adapter-command-routes", "proofkit.cli.hierarchical-command-routes", "proofkit.python-wheel.embedded-cli-contract"}) {
		return fmt.Errorf("adoption front-door change inventory is not exact")
	}
	if record.ChangeRecordRef != "release/change-record.v2.json" {
		return fmt.Errorf("adoption front-door change record reference is not exact")
	}
	changeRecordContent, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(record.ChangeRecordRef)))
	if err != nil {
		return fmt.Errorf("read adoption front-door change record: %w", err)
	}
	digest := sha256.Sum256(changeRecordContent)
	if record.ChangeRecordSHA256 != fmt.Sprintf("sha256:%x", digest) {
		return fmt.Errorf("adoption front-door change record digest is not exact")
	}
	changeRecord, err := releasechange.Read(filepath.Join(root, filepath.FromSlash(record.ChangeRecordRef)))
	if err != nil {
		return fmt.Errorf("admit adoption front-door change record: %w", err)
	}
	if changeRecord.PreviousVersion != record.PreviousVersion || changeRecord.Version != record.Version || !changeRecord.Migration.Required {
		return fmt.Errorf("adoption front-door change record identity is inconsistent")
	}
	wantMigrationSteps := []string{
		"Replace explicit init --preset fresh with adopt plan --mode fresh --repo-root <caller-selected-root>.",
		"Replace init --preset code-baseline with adopt plan --mode code-baseline --repo-root <caller-selected-root>, and replace init --preset code-audit with adopt plan --mode audit-from-code --repo-root <caller-selected-root>.",
		"Replace init --preset legacy with migration-parity-admission followed by migration-plan over explicit caller-owned records; run requirement-source-transition when the migration changes requirement lifecycle state.",
		"Replace init --preset change-set with changed-path-set followed by the explicit impact and selective-gate composition routes required by the consuming repository.",
		"Replace bare init or init --preset all with help families, then select the smallest applicable bounded route rather than materializing every route family.",
		"Regenerate any materialized TypeScript CLI adapter source before invoking a multi-token route such as adopt plan; one-token adapter calls remain compatible.",
	}
	if !slices.Equal(changeRecord.Migration.Steps, wantMigrationSteps) {
		return fmt.Errorf("adoption front-door migration semantics are not exact")
	}
	if !slices.Equal(record.NonClaims, []string{"This owner-authored version-edge observation binds reviewed public contract identities; it does not authenticate Git history, registry publication, provider ingestion, native witness truth, rollout, or production readiness."}) {
		return fmt.Errorf("adoption front-door version-edge non-claims are not exact")
	}
	return nil
}

func equalAdoptionCommandContract(left, right adoptionFrontDoorCommandContract) bool {
	return left.Command == right.Command && left.OutputContractSHA256 == right.OutputContractSHA256 && slices.Equal(left.Route, right.Route)
}

func cloneAdoptionFrontDoorVersionEdge(record adoptionFrontDoorVersionEdge) adoptionFrontDoorVersionEdge {
	record.AddedCommandContracts = append([]adoptionFrontDoorCommandContract(nil), record.AddedCommandContracts...)
	for index := range record.AddedCommandContracts {
		record.AddedCommandContracts[index].Route = append([]string(nil), record.AddedCommandContracts[index].Route...)
	}
	record.AdditionChangeIDs = append([]string(nil), record.AdditionChangeIDs...)
	record.BreakingChangeIDs = append([]string(nil), record.BreakingChangeIDs...)
	record.ChangedGeneratedArtifacts = append([]adoptionChangedGeneratedArtifact(nil), record.ChangedGeneratedArtifacts...)
	record.NonClaims = append([]string(nil), record.NonClaims...)
	return record
}
