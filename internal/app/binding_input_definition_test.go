package app

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const sharedBindingInputDigest = "sha256:123984c0fbb3eeee5020af333f8a5628e10d6aa931b038e42e44fbee92682e1f"

type legacyBindingInputDefinition struct {
	command, id, digest string
	requiredSelection   bool
}

func legacyBindingInputDefinitions() []legacyBindingInputDefinition {
	return []legacyBindingInputDefinition{
		{"evidence-graph", "proofkit.evidence-graph.input.v1.root-shape", "sha256:7ffe236ab203cf411dbfda6008ec8c10cc15691261031d4ed9ed90d81525dc12", false},
		{"proof-slice", "proofkit.proof-slice.input.v1.root-shape", "sha256:71914c95c70dbace0ebce1dc4609624e3b91c994cd8c5adc20ed84d4200f0ac9", true},
	}
}

func restoreSharedBindingInputContract(input map[string]any, legacy legacyBindingInputDefinition) (map[string]any, error) {
	if input["rootDefinitionRef"] != bindingSelectionDefinition || input["rootDefinitionDigest"] != sharedBindingInputDigest {
		return nil, fmt.Errorf("%s does not use the shared binding input definition", legacy.command)
	}
	summary := func(id string) []any {
		return []any{"schemaVersion=1", "root-shape-only definition " + id + "; nested fields, types, and cardinalities are non-claims"}
	}
	if !reflect.DeepEqual(input["compatibilitySummary"], summary(bindingSelectionDefinition)) {
		return nil, fmt.Errorf("%s input summary differs from the shared-reference delta", legacy.command)
	}
	result := clonePublicABIRecord(input)
	result["rootDefinitionRef"], result["rootDefinitionDigest"] = legacy.id, legacy.digest
	result["compatibilitySummary"] = summary(legacy.id)
	return result, nil
}

// Reconstruct only the two removed copies and their parent references. Exact
// predecessor digests keep every other field under the frozen ABI comparison.
func normalizeBindingInputSharingPublicABIDelta(current map[string]any) error {
	definitions, definitionOrder, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		return err
	}
	if !slices.IsSorted(definitionOrder) {
		return fmt.Errorf("binding input reconstruction requires canonical definition order")
	}
	shared, ok := definitions[bindingSelectionDefinition]
	if !ok || shared["canonicalDigest"] != sharedBindingInputDigest {
		return fmt.Errorf("shared binding input definition identity differs")
	}
	actual, err := publicABIDefinitionDigest(shared)
	if err != nil || actual != sharedBindingInputDigest {
		return fmt.Errorf("shared binding input definition content differs")
	}
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	definitionValues := slices.Clone(current["contractDefinitions"].([]any))
	commandValues := slices.Clone(current["commands"].([]any))
	for _, legacy := range legacyBindingInputDefinitions() {
		if _, exists := definitions[legacy.id]; exists {
			return fmt.Errorf("obsolete %s input definition remains", legacy.command)
		}
		command, ok := commands[legacy.command]
		if !ok {
			return fmt.Errorf("%s command is missing", legacy.command)
		}
		input, ok := command["inputContract"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s input contract is invalid", legacy.command)
		}
		restored, err := restoreSharedBindingInputContract(input, legacy)
		if err != nil {
			return err
		}
		definition := clonePublicABIRecord(shared)
		definition["definitionId"] = legacy.id
		tree := clonePublicABIRecord(definition["fieldTree"].(map[string]any))
		variant := clonePublicABIRecord(tree["variants"].([]any)[0].(map[string]any))
		if legacy.requiredSelection {
			variant["requiredFields"] = slices.Clone(variant["allowedFields"].([]any))
		}
		tree["variants"] = []any{variant}
		definition["fieldTree"] = tree
		actual, err := publicABIDefinitionDigest(definition)
		if err != nil || actual != legacy.digest {
			return fmt.Errorf("%s reconstruction differs from its frozen definition", legacy.command)
		}
		definition["canonicalDigest"] = legacy.digest
		definitionValues = append(definitionValues, definition)
		command = clonePublicABIRecord(command)
		command["inputContract"] = restored
		for i, raw := range commandValues {
			if raw.(map[string]any)["command"] == legacy.command {
				commandValues[i] = command
			}
		}
	}
	slices.SortFunc(definitionValues, func(a, b any) int {
		return strings.Compare(a.(map[string]any)["definitionId"].(string), b.(map[string]any)["definitionId"].(string))
	})
	current["contractDefinitions"], current["commands"] = definitionValues, commandValues
	return nil
}

func TestSharedBindingInputDefinitionRejectsCoherentDrift(t *testing.T) {
	if err := normalizeBindingInputSharingPublicABIDelta(readRootOnlyBindingContract(t)); err != nil {
		t.Fatalf("unmodified shared binding owner is invalid: %v", err)
	}
	for _, mutation := range []string{"requiredness", "split-reference", "obsolete-definition", "other-command"} {
		t.Run(mutation, func(t *testing.T) {
			current := readRootOnlyBindingContract(t)
			definitions, _, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "requiredness" {
				shared := definitions[bindingSelectionDefinition]
				variant := shared["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["requiredFields"] = variant["requiredFields"].([]any)[1:]
				changed, err := publicABIDefinitionDigest(shared)
				if err != nil {
					t.Fatal(err)
				}
				shared["canonicalDigest"] = changed
				for _, command := range []string{"requirement-bindings", "evidence-graph", "proof-slice"} {
					mutatePublicABIRecord(t, current, "commands", "command", command, func(row map[string]any) {
						row["inputContract"].(map[string]any)["rootDefinitionDigest"] = changed
					})
				}
			} else if mutation == "other-command" {
				mutatePublicABIRecord(t, current, "commands", "command", "proof-receipt-admission", func(row map[string]any) { row["stdin"] = false })
			} else {
				copy := clonePublicABIRecord(definitions[bindingSelectionDefinition])
				copy["definitionId"] = "proofkit.proof-slice.input.v1.root-shape"
				if mutation == "split-reference" {
					copy["definitionId"] = "proofkit.alternate-binding.input.v1.root-shape"
				}
				changed, err := publicABIDefinitionDigest(copy)
				if err != nil {
					t.Fatal(err)
				}
				copy["canonicalDigest"] = changed
				current["contractDefinitions"] = append(current["contractDefinitions"].([]any), copy)
				slices.SortFunc(current["contractDefinitions"].([]any), func(a, b any) int {
					return strings.Compare(a.(map[string]any)["definitionId"].(string), b.(map[string]any)["definitionId"].(string))
				})
				if mutation == "split-reference" {
					mutatePublicABIRecord(t, current, "commands", "command", "proof-slice", func(row map[string]any) {
						input := row["inputContract"].(map[string]any)
						input["rootDefinitionRef"], input["rootDefinitionDigest"] = copy["definitionId"], changed
					})
				}
			}
			if mutation == "other-command" {
				_, err = sourceCutoverDirectionDelta(readArchivedSourceCutoverPredecessor(t), current)
			} else {
				err = normalizeBindingInputSharingPublicABIDelta(current)
			}
			if err == nil {
				t.Fatal("shared-input correction concealed coherent or unrelated drift")
			}
			if mutation == "split-reference" && err.Error() != "proof-slice does not use the shared binding input definition" {
				t.Fatalf("split owner was rejected by an unrelated predicate: %v", err)
			}
		})
	}
}
