package app

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
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
	if err := verifyAdditivePublicABIDiff(frozen, readCLIContractRaw(t), []string{"integration-check", "integration-source"}, integrationProcessAppendices()); err != nil {
		t.Fatal(err)
	}
	if current := "sha256:" + currentCLIContractPublicABISHA256(t); current == frozen.PublicABISHA256 {
		t.Fatal("new public commands retained the previous complete ABI identity")
	}

	change, err := releasechange.Read(filepath.Join(repoRoot(t), releasechange.RecordPath))
	if err != nil {
		t.Fatal(err)
	}
	if change.PreviousVersion != frozen.ReleaseVersion || change.Version != "0.10.0" || change.ChangeClass != "compatible" || len(change.BreakingChanges) != 0 || change.Migration.Required || len(change.Migration.Steps) != 0 || !slices.Equal(releaseChangeIDs(change.Additions), []string{"proofkit.agent-integration.freshness", "proofkit.agent-integration.source"}) {
		t.Fatal("integration release record does not describe the exact compatible addition")
	}
	file, err := os.Open(filepath.Join(repoRoot(t), "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	manifest, err := admission.DecodeTypedJSON[struct {
		Version string `json:"version"`
	}](file, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != change.Version {
		t.Fatal("integration package version differs from its release record")
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
