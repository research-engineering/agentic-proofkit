package app

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// This inventory is reviewed against the archived 0.14.21 public contract.
// Native source byte digests are freshness evidence, not wire semantics.
var sourceCutoverDirectionDeltas = []string{
	"adopt-materialize-apply/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"adopt-materialize-plan/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"evidence-graph/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"proof-slice/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-authoring-plan/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-authoring-plan/output:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-bindings/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-browser-server/input:childDefinitionBindings,compatibilitySummary,contractId,nativeAdmissionWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-browser-server/output:compatibilitySummary,contractId,handoffClauses,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-context-compose/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-context-compose/output:childDefinitionBindings,compatibilitySummary,contractId,nativeOutputWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-context-slice/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-context-slice/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-input-compose/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-input-compose/output:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-view/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-view/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-impact-input-compose/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-semantic-diff/input:compatibilitySummary,contractId,nativeAdmissionWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-semantic-diff/output:compatibilitySummary,contractId,nativeOutputWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-admission/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-admission/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-transition/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-transition/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-view/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-view/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-spec-tree-view/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef",
	"requirement-spec-tree/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef",
	"requirement-traceability-graph/input:compatibilitySummary,contractId,nativeAdmissionWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"spec-overview-claims/input:compatibilitySummary,contractId,pathRelations",
	"test-evidence-inventory/input:childDefinitionBindings,compatibilitySummary,contractId,projectionVariants,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"view/output:compatibilitySummary,contractId,handoffClauses",
}

var nativeBoundaryDirectionDeltas = []string{
	"typescript-public-api-surfaces/input:compatibilitySummary,nonClaims,sourceGrammar",
}

func TestPublicVersionEdgesCloseDirectionDeltas(t *testing.T) {
	previous := readArchivedSourceCutoverPredecessor(t)
	current := readCLIContractRaw(t)
	got, err := sourceCutoverDirectionDelta(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(sourceCutoverDirectionDeltas), nativeBoundaryDirectionDeltas...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("undeclared public direction delta\n got: %v\nwant: %v", got, want)
	}
	previousDefinitions, _, err := indexPublicABIRecords(previous["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	currentDefinitions, _, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	if removed, added := differenceKeys(previousDefinitions, currentDefinitions), differenceKeys(currentDefinitions, previousDefinitions); len(removed) != 30 || len(added) != 26 {
		t.Fatalf("public definition replacement is incomplete: removed=%v added=%v", removed, added)
	}
	for id, prior := range previousDefinitions {
		if next, exists := currentDefinitions[id]; exists && !reflect.DeepEqual(prior, next) {
			t.Fatalf("unchanged definition %s was modified", id)
		}
	}
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]struct{}{}
	var visit func(string) error
	visit = func(id string) error {
		if _, exists := used[id]; exists {
			return nil
		}
		definition, exists := currentDefinitions[id]
		if !exists {
			return fmt.Errorf("public direction references missing definition %s", id)
		}
		used[id] = struct{}{}
		for _, raw := range definition["definitionRefs"].([]any) {
			if err := visit(raw.(string)); err != nil {
				return err
			}
		}
		return nil
	}
	for _, command := range commands {
		for _, direction := range []string{"inputContract", "outputContract"} {
			if record, present := command[direction].(map[string]any); present {
				if err := visit(record["rootDefinitionRef"].(string)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if len(used) != len(currentDefinitions) {
		t.Fatalf("reachable definitions=%d, public inventory=%d", len(used), len(currentDefinitions))
	}
}

func sourceCutoverDirectionDelta(previous, current map[string]any) ([]string, error) {
	priorEnvelope, nextEnvelope := clonePublicABIRecord(previous), clonePublicABIRecord(current)
	delete(priorEnvelope, "commands")
	delete(priorEnvelope, "contractDefinitions")
	delete(nextEnvelope, "commands")
	delete(nextEnvelope, "contractDefinitions")
	if !reflect.DeepEqual(priorEnvelope, nextEnvelope) {
		return nil, fmt.Errorf("public contract header or process changed outside the source cutover")
	}
	priorCommands, priorOrder, err := indexPublicABIRecords(previous["commands"], "command")
	if err != nil {
		return nil, err
	}
	nextCommands, nextOrder, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return nil, err
	}
	if !slices.Equal(priorOrder, nextOrder) {
		return nil, fmt.Errorf("public command inventory or order changed without declaration")
	}
	changed := []string{}
	for _, name := range priorOrder {
		prior, err := normalizePublicABICommandFingerprint(priorCommands[name])
		if err != nil {
			return nil, err
		}
		next, err := normalizePublicABICommandFingerprint(nextCommands[name])
		if err != nil {
			return nil, err
		}
		for _, direction := range []string{"inputContract", "outputContract"} {
			before, beforeExists := prior[direction].(map[string]any)
			after, afterExists := next[direction].(map[string]any)
			if beforeExists != afterExists {
				return nil, fmt.Errorf("%s %s presence changed", name, direction)
			}
			if beforeExists {
				fields := []string{}
				for key := range before {
					if !reflect.DeepEqual(before[key], after[key]) {
						fields = append(fields, key)
					}
				}
				for key := range after {
					if _, exists := before[key]; !exists {
						fields = append(fields, key)
					}
				}
				slices.Sort(fields)
				if len(fields) > 0 {
					label := "input"
					if direction == "outputContract" {
						label = "output"
					}
					changed = append(changed, name+"/"+label+":"+strings.Join(fields, ","))
				}
			}
			delete(prior, direction)
			delete(next, direction)
		}
		if !reflect.DeepEqual(prior, next) {
			return nil, fmt.Errorf("%s command-level CLI behavior changed without declaration", name)
		}
	}
	slices.Sort(changed)
	return changed, nil
}
