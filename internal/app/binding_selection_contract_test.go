package app

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const bindingSelectionDefinition = "proofkit.requirement-bindings.input.v1.root-shape"
const oldBindingSelectionDigest = "sha256:e7da70a2267f2ca13771e864bba6a1a0416132c2d56decb5db9f9694de021daf"

// Normalize only the reviewed removal of selection from required root fields.
// The unchanged frozen predecessor still checks every other contract operand.
func normalizeBindingSelectionPublicABIDelta(current map[string]any) error {
	definitions, _, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		return err
	}
	definition, ok := definitions[bindingSelectionDefinition]
	if !ok {
		return fmt.Errorf("binding selection definition is missing")
	}
	definition = clonePublicABIRecord(definition)
	tree, ok := definition["fieldTree"].(map[string]any)
	if !ok {
		return fmt.Errorf("binding selection field tree is invalid")
	}
	variants, ok := tree["variants"].([]any)
	if !ok || len(variants) != 1 {
		return fmt.Errorf("binding selection variants differ")
	}
	variant, ok := variants[0].(map[string]any)
	if !ok {
		return fmt.Errorf("binding selection variant is invalid")
	}
	allowed := []any{"bindingId", "bindings", "nonClaims", "requirements", "schemaVersion", "selection", "witnessCommands"}
	required := []any{"bindingId", "bindings", "nonClaims", "requirements", "schemaVersion", "witnessCommands"}
	if !reflect.DeepEqual(variant["allowedFields"], allowed) || !reflect.DeepEqual(variant["requiredFields"], required) {
		return fmt.Errorf("binding selection root fields differ from the declared correction")
	}
	newDigest, ok := definition["canonicalDigest"].(string)
	if !ok || newDigest == oldBindingSelectionDigest {
		return fmt.Errorf("binding selection correction lacks a distinct digest")
	}
	delete(definition, "canonicalDigest")
	encoded, err := stablejson.MarshalLayout(definition, stablejson.LayoutCompact)
	if err != nil || digest.SHA256BytesRef(bytes.TrimSuffix(encoded, []byte{'\n'})) != newDigest {
		return fmt.Errorf("binding selection definition digest is stale")
	}
	tree, variant = clonePublicABIRecord(tree), clonePublicABIRecord(variant)
	variant["requiredFields"] = allowed
	tree["variants"] = []any{variant}
	definition["fieldTree"] = tree
	definition["canonicalDigest"] = oldBindingSelectionDigest
	values := slices.Clone(current["contractDefinitions"].([]any))
	for i, raw := range values {
		if raw.(map[string]any)["definitionId"] == bindingSelectionDefinition {
			values[i] = definition
		}
	}
	current["contractDefinitions"] = values
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	command, ok := commands["requirement-bindings"]
	if !ok {
		return fmt.Errorf("binding command is missing")
	}
	input, ok := command["inputContract"].(map[string]any)
	if !ok || input["rootDefinitionRef"] != bindingSelectionDefinition || input["rootDefinitionDigest"] != newDigest {
		return fmt.Errorf("binding input does not bind the corrected definition")
	}
	input, command = clonePublicABIRecord(input), clonePublicABIRecord(command)
	input["rootDefinitionDigest"] = oldBindingSelectionDigest
	command["inputContract"] = input
	values = slices.Clone(current["commands"].([]any))
	for i, raw := range values {
		if raw.(map[string]any)["command"] == "requirement-bindings" {
			values[i] = command
		}
	}
	current["commands"] = values
	return nil
}

func TestBindingSelectionContractMatchesNativeCLI(t *testing.T) {
	input := readJSONFile(t, "proofkit/requirement-bindings.json").(map[string]any)
	delete(input, "selection")
	baseline := runAdoptionHelpCLI(t, adoptionHelpJSON(t, input), "requirement-bindings", "--input", "-")
	for _, selection := range []any{nil, map[string]any{}, map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}}} {
		input["selection"] = selection
		actual := runAdoptionHelpCLI(t, adoptionHelpJSON(t, input), "requirement-bindings", "--input", "-")
		if !reflect.DeepEqual(actual, baseline) {
			t.Fatal("empty selection forms do not preserve the whole report")
		}
	}
	for _, invalid := range []any{true, "all", map[string]any{"unknown": []any{}}} {
		input["selection"] = invalid
		code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"requirement-bindings", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, input)), PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" {
			t.Fatal("invalid selection was admitted")
		}
	}
	contract := readCLIContractRaw(t)
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
			current := readCLIContractRaw(t)
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
	current := readCLIContractRaw(t)
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
	if err := normalizeBindingSelectionPublicABIDelta(current); err == nil || err.Error() != "binding selection root fields differ from the declared correction" {
		t.Fatalf("coherent requiredness drift was not rejected by the field-set predicate: %v", err)
	}
}
