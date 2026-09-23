package app

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const bindingSelectionDefinition = "proofkit.requirement-bindings.input.v1.root-shape"
const oldBindingSelectionDigest = "sha256:e7da70a2267f2ca13771e864bba6a1a0416132c2d56decb5db9f9694de021daf"

// Normalize only the reviewed removal of selection from required root fields.
// The unchanged frozen predecessor still checks every other contract operand.
func normalizeBindingSelectionPublicABIDelta(current map[string]any) error {
	return normalizeOptionalInputFieldPublicABIDelta(current, "requirement-bindings", "selection", oldBindingSelectionDigest)
}

func TestBindingSelectionContractMatchesNativeCLI(t *testing.T) {
	for _, command := range []string{"requirement-bindings", "evidence-graph", "proof-slice"} {
		t.Run(command, func(t *testing.T) {
			input := readJSONFile(t, "proofkit/requirement-bindings.json").(map[string]any)
			delete(input, "selection")
			baseline := runAdoptionHelpCLI(t, adoptionHelpJSON(t, input), command, "--input", "-")
			requirementCount := len(input["requirements"].([]any))
			if requirementCount == 0 {
				t.Fatal("selection equivalence needs a nonempty requirement set")
			}
			if command == "proof-slice" && len(baseline["selectedRequirements"].([]any)) != requirementCount {
				t.Fatal("absent selection did not retain every requirement")
			}
			if command == "evidence-graph" && len(baseline["requirements"].([]any)) != requirementCount {
				t.Fatal("graph lost an admitted requirement")
			}
			for _, selection := range []any{nil, map[string]any{}, map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}}} {
				input["selection"] = selection
				actual := runAdoptionHelpCLI(t, adoptionHelpJSON(t, input), command, "--input", "-")
				if !reflect.DeepEqual(actual, baseline) {
					t.Fatal("empty selection forms do not preserve the whole output")
				}
			}
			for _, invalid := range []any{true, "all", []any{}, map[string]any{"unknown": []any{}}} {
				input["selection"] = invalid
				code, output, diagnostic := executeAgentWorkflowCLI(t, []string{command, "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, input)), PresentationCapabilities{})
				if code != 1 || output != "" || diagnostic == "" {
					t.Fatal("invalid selection was admitted")
				}
			}
		})
	}
	contract := readArchivedSourceCutoverPredecessor(t)
	before := adoptionHelpJSON(t, contract)
	if err := verifyManagedIntegrationPublicABIDiff(readFrozenManagedIntegrationPredecessor(t), contract); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, adoptionHelpJSON(t, contract)) {
		t.Fatal("historical comparison mutated the current contract")
	}
}

func TestBindingSelectionCorrectionRejectsUndeclaredDrift(t *testing.T) {
	for _, mutation := range []string{"required-selection", "missing-required", "missing-allowed", "stale-digest", "other-command"} {
		t.Run(mutation, func(t *testing.T) {
			current := readArchivedSourceCutoverPredecessor(t)
			mutatePublicABIRecord(t, current, "contractDefinitions", "definitionId", bindingSelectionDefinition, func(record map[string]any) {
				variant := record["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				switch mutation {
				case "required-selection":
					variant["requiredFields"] = variant["allowedFields"]
				case "missing-required":
					variant["requiredFields"] = variant["requiredFields"].([]any)[1:]
				case "missing-allowed":
					variant["allowedFields"] = variant["requiredFields"]
				case "stale-digest":
					record["canonicalDigest"] = oldBindingSelectionDigest
				}
			})
			if mutation == "other-command" {
				mutatePublicABIRecord(t, current, "commands", "command", "proof-receipt-admission", func(record map[string]any) { record["stdin"] = false })
			}
			if verifyManagedIntegrationPublicABIDiff(readFrozenManagedIntegrationPredecessor(t), current) == nil {
				t.Fatal("correction concealed an undeclared change")
			}
		})
	}
}

func TestBindingSelectionCorrectionRejectsCoherentRequirednessDrift(t *testing.T) {
	current := readArchivedSourceCutoverPredecessor(t)
	var changedDigest string
	mutatePublicABIRecord(t, current, "contractDefinitions", "definitionId", bindingSelectionDefinition, func(record map[string]any) {
		variant := record["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
		variant["requiredFields"] = variant["requiredFields"].([]any)[1:]
		delete(record, "canonicalDigest")
		encoded, err := stablejson.MarshalLayout(record, stablejson.LayoutCompact)
		if err != nil {
			t.Fatal(err)
		}
		changedDigest = digest.SHA256BytesRef(bytes.TrimSuffix(encoded, []byte{'\n'}))
		record["canonicalDigest"] = changedDigest
	})
	mutatePublicABIRecord(t, current, "commands", "command", "requirement-bindings", func(record map[string]any) {
		record["inputContract"].(map[string]any)["rootDefinitionDigest"] = changedDigest
	})
	if err := normalizeBindingSelectionPublicABIDelta(current); err == nil || err.Error() != "optional-field correction changes other root fields" {
		t.Fatalf("coherent requiredness drift was not rejected by the field-set predicate: %v", err)
	}
}
