package app

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

func readFrozenIntegrationPublicABI(t *testing.T) frozenPublicABI {
	t.Helper()
	return readFrozenPublicABI(t, "internal/app/testdata/releases/v0.9.0/public-abi-observation.json",
		"633f68f322e942902d8ccf10468d298bdf70f6692390ef1bfa24190538b90fc3", "0.9.0",
		"sha256:9a6842b45a218d6caa5da517b0b20f861e13c35a2900e92d34361cdf771781f7")
}

func integrationProcessAppendices() map[string]string {
	return map[string]string{
		"stdout": " Integration check also emits exactly one classified JSON value or text report with exit 2 for missing, stale, or invalid; current exits 0, and operational errors exit 1.",
		"stderr": " Integration check classified exit-2 reports leave stderr empty; operational or invocation errors use non-disclosing stderr diagnostics.",
	}
}

func TestIntegrationVersionEdgeClosesCompletePublicABIDiff(t *testing.T) {
	frozen := readFrozenIntegrationPublicABI(t)
	if err := verifyAdditivePublicABIDiff(frozen, readArchivedProjectNavigationContract(t), []string{}, nil); err != nil {
		t.Fatalf("frozen predecessor fingerprints differ from archived release bytes: %v", err)
	}
	if err := verifyAdditivePublicABIDiff(frozen, readArchivedIntegrationContract(t), []string{"integration-check", "integration-source"}, integrationProcessAppendices()); err != nil {
		t.Fatal(err)
	}
	if current := "sha256:" + currentCLIContractPublicABISHA256(t); current == frozen.PublicABISHA256 {
		t.Fatal("new public commands retained the previous complete ABI identity")
	}

	changePath := filepath.Join(repoRoot(t), "internal/app/testdata/releases/v0.10.0", releasechange.RecordPath)
	content, err := os.ReadFile(changePath)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(content)) != "9240098569e1fcc1d9cd8137e1184a97a9ad31f10649dfff901f2d66d7f2b81b" {
		t.Fatalf("archived integration release bytes changed: %v", err)
	}
	change, err := releasechange.Read(changePath)
	if err != nil {
		t.Fatal(err)
	}
	if change.PreviousVersion != frozen.ReleaseVersion || change.Version != "0.10.0" || change.ChangeClass != "compatible" || len(change.BreakingChanges) != 0 || change.Migration.Required || len(change.Migration.Steps) != 0 || !slices.Equal(releaseChangeIDs(change.Additions), []string{"proofkit.agent-integration.freshness", "proofkit.agent-integration.source"}) {
		t.Fatal("integration release record does not describe the exact compatible addition")
	}
	contracts, err := currentVersionEdgeCommandContracts(repoRoot(t), []string{"integration-check", "integration-source"})
	if err != nil {
		t.Fatal(err)
	}
	for _, contract := range contracts {
		if contract.InputContract != nil || contract.OutputContract.ContractID != "proofkit."+contract.Command+".output.v1" || commandroute.Text(contract.Route) != "integration "+contract.Command[len("integration-"):] {
			t.Fatalf("integration command does not expose its exact no-input route and output contract: %s", contract.Command)
		}
	}
}

func readArchivedIntegrationContract(t *testing.T) map[string]any {
	t.Helper()
	return readArchivedCLIContract(t, "internal/app/testdata/releases/v0.10.1", "846a642fbe1bfb9a59502c7018788667b5b6bd711e5fc45534f1846bc440e344")
}

func readFrozenManagedIntegrationPredecessor(t *testing.T) frozenPublicABI {
	t.Helper()
	return readFrozenPublicABI(t, "internal/app/testdata/releases/v0.10.1/public-abi-observation.json",
		"1e7efe0e9e960911b54b2045504122ca3bd9355316ff2201e7ad1e19a2e76592", "0.10.1",
		"sha256:cc1fc5a55e00ea13e92d82edc3a3e3115cd9e69a00d08618fe2b1cefd25216d2")
}

const managedReplayPolicy = "Replay requires a retained generation-2 terminal receipt binding the exact desiredStateId under the native lock; generation-1 receipts remain recoverable but acknowledgement retries require a newly reviewed plan. Roots with generation-2 receipts require a supporting binary even after recovery completes."

func verifyManagedIntegrationPublicABIDiff(frozen frozenPublicABI, current map[string]any) error {
	current = clonePublicABIRecord(current)
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	command, ok := commands["adopt-materialize-apply"]
	if !ok {
		return fmt.Errorf("materialization apply command is missing")
	}
	output, ok := command["outputContract"].(map[string]any)
	if !ok {
		return fmt.Errorf("materialization apply output contract is missing")
	}
	summary, ok := output["compatibilitySummary"].([]any)
	if !ok || len(summary) == 0 || summary[len(summary)-1] != managedReplayPolicy {
		return fmt.Errorf("materialization apply replay policy differs from its declared delta")
	}
	command = clonePublicABIRecord(command)
	output = clonePublicABIRecord(output)
	output["compatibilitySummary"] = summary[:len(summary)-1]
	command["outputContract"] = output
	values := slices.Clone(current["commands"].([]any))
	for index, raw := range values {
		if raw.(map[string]any)["command"] == "adopt-materialize-apply" {
			values[index] = command
		}
	}
	current["commands"] = values
	return verifyAdditivePublicABIDiff(frozen, current, []string{"integration-apply", "integration-plan", "integration-recover"}, nil)
}

func TestManagedIntegrationVersionEdgeClosesDeclaredPublicABIDelta(t *testing.T) {
	frozen := readFrozenManagedIntegrationPredecessor(t)
	if err := verifyAdditivePublicABIDiff(frozen, readArchivedIntegrationContract(t), []string{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifyManagedIntegrationPublicABIDiff(frozen, readCLIContractRaw(t)); err != nil {
		t.Fatal(err)
	}
	if current := "sha256:" + currentCLIContractPublicABISHA256(t); current == frozen.PublicABISHA256 {
		t.Fatal("managed lifecycle retained the predecessor semantic ABI identity")
	}
}
