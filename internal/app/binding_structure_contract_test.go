package app

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
)

const bindingStructureDefinition = "proofkit.requirement-bindings.input.v1.json-schema"
const bindingStructureDigest = "sha256:497bd33e52ee403158f1fc4b2da3a502042163282639e183dcd7fe503913dbdc"

func restoreBindingStructureContract(input map[string]any) (map[string]any, error) {
	if input["rootDefinitionRef"] != bindingStructureDefinition || input["rootDefinitionDigest"] != bindingStructureDigest {
		return nil, fmt.Errorf("binding input structural identity differs")
	}
	if !reflect.DeepEqual(input["compatibilitySummary"], []any{
		"schemaVersion=1",
		"structural JSON Schema definition " + bindingStructureDefinition + "; canonicalization and semantic validity remain native admission obligations",
	}) {
		return nil, fmt.Errorf("binding input structural scope differs")
	}
	result := clonePublicABIRecord(input)
	result["rootDefinitionRef"], result["rootDefinitionDigest"] = bindingSelectionDefinition, sharedBindingInputDigest
	result["compatibilitySummary"] = []any{"schemaVersion=1", "root-shape-only definition " + bindingSelectionDefinition + "; nested fields, types, and cardinalities are non-claims"}
	return result, nil
}

// Both endpoints are bound to independent frozen digests. This is a reversal of
// one admitted enrichment, not a generic omission of nested schema semantics.
func normalizeBindingStructurePublicABIDelta(current map[string]any) error {
	definitions, order, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		return err
	}
	if !slices.IsSorted(order) {
		return fmt.Errorf("binding structure reversal requires canonical definition order")
	}
	definition, present := definitions[bindingStructureDefinition]
	if !present {
		// Subsequent historical-delta tests may already hold the restored form.
		return nil
	}
	actual, err := publicABIDefinitionDigest(definition)
	if err != nil || actual != bindingStructureDigest || definition["canonicalDigest"] != bindingStructureDigest {
		return fmt.Errorf("binding structural definition differs from the admitted enrichment")
	}
	if _, old := definitions[bindingSelectionDefinition]; old {
		return fmt.Errorf("obsolete binding root definition remains")
	}
	restored := clonePublicABIRecord(definition)
	restored["definitionId"] = bindingSelectionDefinition
	tree := clonePublicABIRecord(restored["fieldTree"].(map[string]any))
	variant := clonePublicABIRecord(tree["variants"].([]any)[0].(map[string]any))
	delete(variant, "schema")
	tree["variants"] = []any{variant}
	tree["kind"] = "root_shape_only"
	tree["nonClaims"] = []any{
		"Root-shape definitions do not claim nested field shapes, leaf types, cardinalities, or semantic validity.",
		"Root-shape definitions do not replace direct public-CLI runtime witnesses for variant selection.",
	}
	restored["fieldTree"] = tree
	actual, err = publicABIDefinitionDigest(restored)
	if err != nil || actual != sharedBindingInputDigest {
		return fmt.Errorf("binding root reconstruction differs from the exact predecessor")
	}
	restored["canonicalDigest"] = sharedBindingInputDigest
	commands := slices.Clone(current["commands"].([]any))
	seen := map[string]bool{}
	for i, raw := range commands {
		command := raw.(map[string]any)
		name := command["command"].(string)
		for _, direction := range []string{"input", "output"} {
			input, _ := command[direction+"Contract"].(map[string]any)
			consumer := direction == "input" && slices.Contains([]string{"evidence-graph", "proof-slice", "requirement-bindings"}, name)
			if consumer != (input["rootDefinitionRef"] == bindingStructureDefinition) {
				return fmt.Errorf("binding structural consumer differs: %s %s", name, direction)
			}
			if !consumer {
				continue
			}
			restoredInput, err := restoreBindingStructureContract(input)
			if err != nil {
				return err
			}
			command = clonePublicABIRecord(command)
			command["inputContract"] = restoredInput
			commands[i] = command
			seen[name] = true
		}
	}
	if len(seen) != 3 {
		return fmt.Errorf("binding structural consumer set is incomplete")
	}
	values := slices.Clone(current["contractDefinitions"].([]any))
	for i, raw := range values {
		if raw.(map[string]any)["definitionId"] == bindingStructureDefinition {
			values[i] = restored
		}
	}
	slices.SortFunc(values, func(a, b any) int {
		return strings.Compare(a.(map[string]any)["definitionId"].(string), b.(map[string]any)["definitionId"].(string))
	})
	current["contractDefinitions"], current["commands"] = values, commands
	return nil
}

func readRootOnlyBindingContract(t *testing.T) map[string]any {
	t.Helper()
	current := readCLIContractRaw(t)
	if err := normalizeBindingStructurePublicABIDelta(current); err != nil {
		t.Fatal(err)
	}
	return current
}

func TestBindingStructuralContractMatchesNativeOwner(t *testing.T) {
	contract := readCLIContractRaw(t)
	definitions, _, err := indexPublicABIRecords(contract["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	definition, ok := definitions[bindingStructureDefinition]
	if !ok {
		t.Fatal("public binding structural definition is missing")
	}
	variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(canonicalJSONValue(t, variant["schema"]), canonicalJSONValue(t, requirementbinding.InputStructure())) {
		t.Fatal("shipped structural schema is not the exact native projection")
	}
	if err := normalizeBindingStructurePublicABIDelta(contract); err != nil {
		t.Fatal(err)
	}
}

func TestBindingStructuralDeltaCannotConcealNestedDrift(t *testing.T) {
	for _, mutation := range []string{"nested-type", "root-closedness", "version", "summary", "fourth-consumer", "missing-consumer", "direction"} {
		t.Run(mutation, func(t *testing.T) {
			current := readCLIContractRaw(t)
			mutatePublicABIRecord(t, current, "contractDefinitions", "definitionId", bindingStructureDefinition, func(definition map[string]any) {
				schema := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
				switch mutation {
				case "nested-type":
					schema["properties"].(map[string]any)["nonClaims"].(map[string]any)["items"] = map[string]any{"type": "boolean"}
				case "root-closedness":
					schema["additionalProperties"] = true
				case "version":
					definition["schemaVersion"] = 2
				}
				changed, err := publicABIDefinitionDigest(definition)
				if err != nil {
					t.Fatal(err)
				}
				definition["canonicalDigest"] = changed
				for _, command := range []string{"requirement-bindings", "evidence-graph", "proof-slice"} {
					mutatePublicABIRecord(t, current, "commands", "command", command, func(row map[string]any) { row["inputContract"].(map[string]any)["rootDefinitionDigest"] = changed })
				}
			})
			switch mutation {
			case "summary", "missing-consumer", "direction":
				mutatePublicABIRecord(t, current, "commands", "command", "proof-slice", func(row map[string]any) {
					input := row["inputContract"].(map[string]any)
					switch mutation {
					case "summary":
						input["compatibilitySummary"] = []any{"schema proves semantic validity"}
					case "missing-consumer":
						input["rootDefinitionRef"] = bindingSelectionDefinition
					case "direction":
						row["outputContract"] = clonePublicABIRecord(input)
					}
				})
			case "fourth-consumer":
				mutatePublicABIRecord(t, current, "commands", "command", "proof-receipt-admission", func(row map[string]any) {
					row["inputContract"].(map[string]any)["rootDefinitionRef"] = bindingStructureDefinition
				})
			}
			if err := normalizeBindingStructurePublicABIDelta(current); err == nil {
				t.Fatal("structural enrichment concealed undeclared change")
			}
		})
	}
}
