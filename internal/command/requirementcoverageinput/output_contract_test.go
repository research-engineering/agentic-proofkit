package requirementcoverageinput

import (
	"bytes"
	"os"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestNormalizedComposeOutputFitsPublishedClosedRoot(t *testing.T) {
	output, code, err := Build(validComposeInput(t, baseInventoryEntries()))
	if err != nil || code != 0 {
		t.Fatalf("normalized output: %v, exit=%d", err, code)
	}
	if _, present := output["normalizedTestEvidenceInventory"]; !present {
		t.Fatal("normalized output lost retained inventory provenance")
	}
	content, err := os.ReadFile("../../../proofkit/cli-contract.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(content), 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	contract := decoded.(map[string]any)
	const definitionID = "proofkit.requirement-coverage-input-compose.output.v3.root-shape"
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		if definition["definitionId"] != definitionID {
			continue
		}
		variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
		allowed := variant["allowedFields"].([]any)
		for key := range output {
			if !slices.Contains(allowed, any(key)) {
				t.Fatalf("successful output field %s is forbidden by closed root", key)
			}
		}
		if slices.Contains(variant["requiredFields"].([]any), any("normalizedTestEvidenceInventory")) {
			t.Fatal("normalized-only provenance became required for direct mode")
		}
		return
	}
	t.Fatal("coverage compose output definition is absent")
}
