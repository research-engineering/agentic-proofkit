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
	"adopt-materialize-apply/input:childDefinitionBindings,compatibilitySummary,contractId,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"adopt-materialize-plan/input:childDefinitionBindings,compatibilitySummary,contractId,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
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
	"requirement-coverage-input-compose/input:childDefinitionBindings,commonRequiredFields,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-input-compose/output:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-view/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-coverage-view/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-impact-input-compose/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-proof-resolver/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-proof-source-set/output:childDefinitionBindings",
	"requirement-proof-view/input:childDefinitionBindings",
	"requirement-semantic-diff/input:compatibilitySummary,contractId,nativeAdmissionWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-semantic-diff/output:compatibilitySummary,contractId,nativeOutputWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-admission/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-admission/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-transition/input:childDefinitionBindings,compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-transition/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-view/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-source-view/output:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-spec-tree-view/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef",
	"requirement-spec-tree-view/output:compatibilitySummary,nativeOutputWitnessSelector,rootDefinitionDigest,rootDefinitionRef",
	"requirement-spec-tree/input:compatibilitySummary,contractId,rootDefinitionDigest,rootDefinitionRef",
	"requirement-spec-tree/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-traceability-graph/input:compatibilitySummary,contractId,nativeAdmissionWitnessSelector,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"requirement-traceability-graph/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"spec-overview-claims/input:compatibilitySummary,contractId,pathRelations",
	"test-evidence-inventory/input:childDefinitionBindings,compatibilitySummary,contractId,projectionVariants,rootDefinitionDigest,rootDefinitionRef,schemaVersion",
	"view/output:compatibilitySummary,contractId,handoffClauses",
}

var nativeBoundaryDirectionDeltas = []string{
	"evidence-graph/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"proof-slice/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-bindings/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-proof-resolver/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"witness-plan/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef,variants",
	"witness-plan/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"witness-scheduler-plan/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"witness-scheduler-plan/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"adoption-checklist/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"adoption-checklist/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"binding-partition/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"binding-partition/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"completion-criteria/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"completion-criteria/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"package-runtime-dependency-admission/input:compatibilitySummary,packageResolutionRequiredFields,rootDefinitionDigest,rootDefinitionRef",
	"package-runtime-dependency-admission/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"proof-obligation-algebra/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"proof-obligation-algebra/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"text-policy/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"text-policy/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"custom-rule-boundary/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"custom-rule-boundary/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"document-lifecycle-boundary/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"document-lifecycle-boundary/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"rendered-artifact-freshness/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"rendered-artifact-freshness/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"proof-receipt-admission/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"proof-receipt-admission/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"receipt-producer-admission/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"receipt-producer-admission/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"branch-authority/input:compatibilitySummary,nativeAdmissionWitnessSelector,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef",
	"branch-authority/output:compatibilitySummary,nativeOutputWitnessSelector,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef",
	"receipt-currentness-scope/input:compatibilitySummary,nativeAdmissionWitnessSelector,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef",
	"receipt-currentness-scope/output:compatibilitySummary,nativeOutputWitnessSelector,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef",
	"receipt-trust-class/input:compatibilitySummary,nativeAdmissionWitnessSelector,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef",
	"receipt-trust-class/output:compatibilitySummary,nativeOutputWitnessSelector,nativeSource,nativeSources,rootDefinitionDigest,rootDefinitionRef",
	"selective-gate-plan/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"selective-gate-plan/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"selective-gate-evidence/input:childDefinitionBindings,compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"selective-gate-evidence/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"selective-gate-obligation-decision-input/input:childDefinitionBindings,compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"selective-gate-obligation-decision-input/output:childDefinitionBindings,compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"obligation-decision/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"obligation-decision/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"impact/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"impact/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"requirement-impact-input-compose/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"adopt-materialize-apply/output:compatibilitySummary,contractId,nativeSources",
	"adopt-materialize-plan/output:compatibilitySummary,contractId,nativeSources",
	"adopt-materialize-recover/output:compatibilitySummary,contractId,nativeSources",
	"external-consumer/input:compatibilitySummary,contractId,nativeSource,nativeSources",
	"external-consumer/output:nativeSource,nativeSources",
	"integration-apply/output:compatibilitySummary,contractId,nativeSources",
	"integration-plan/output:compatibilitySummary,contractId,nativeSources",
	"integration-recover/output:compatibilitySummary,contractId,nativeSources",
	"registry-consumer/input:compatibilitySummary,contractId,nativeSource,nativeSources",
	"registry-consumer/output:nativeSource,nativeSources",
	"registry-consumer-proof-input-compose/input:compatibilitySummary,contractId,nativeSource,nativeSources",
	"registry-consumer-proof-input-compose/output:nativeSource,nativeSources",
	"typescript-public-api-surfaces/input:compatibilitySummary,nonClaims,rootDefinitionDigest,rootDefinitionRef,sourceGrammar",
	"typescript-public-api-surfaces/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"workspace-changed-package-plan/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"workspace-changed-package-plan/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"workspace-manifest-facts/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"workspace-manifest-facts/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"workspace-shard-partition/input:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
	"workspace-shard-partition/output:compatibilitySummary,rootDefinitionDigest,rootDefinitionRef",
}

func TestIntegrityInputSemanticVersionsPreserveWireShapes(t *testing.T) {
	previous := readArchivedSourceCutoverPredecessor(t)
	current := readCLIContractRaw(t)
	before, _, err := indexPublicABIRecords(previous["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"external-consumer", "registry-consumer", "registry-consumer-proof-input-compose"} {
		t.Run(name, func(t *testing.T) {
			prior := before[name]["inputContract"].(map[string]any)
			next := after[name]["inputContract"].(map[string]any)
			if prior["contractId"] != "proofkit."+name+".input.v1" || next["contractId"] != "proofkit."+name+".input.v2" {
				t.Fatal("narrowed integrity domain must have a new input semantic identity")
			}
			for _, field := range []string{"schemaVersion", "rootDefinitionRef", "rootDefinitionDigest"} {
				if !reflect.DeepEqual(prior[field], next[field]) {
					t.Fatalf("unchanged wire field %s changed", field)
				}
			}
			if before[name]["outputContract"].(map[string]any)["contractId"] != after[name]["outputContract"].(map[string]any)["contractId"] {
				t.Fatal("output identity changed without a wire-shape change")
			}
		})
	}
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
	if err := verifyResidueDefinitionAdditions(previousDefinitions, currentDefinitions); err != nil {
		t.Fatal(err)
	}
	if removed, added := differenceKeys(previousDefinitions, currentDefinitions), differenceKeys(currentDefinitions, previousDefinitions); len(removed) != 89 || len(added) != 85+len(residueCommandAdditions) {
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
	expectedOrder := slices.Clone(priorOrder)
	for _, addition := range residueCommandAdditions {
		if _, exists := priorCommands[addition.command]; exists {
			return nil, fmt.Errorf("declared added command already exists in predecessor")
		}
		expectedOrder = append(expectedOrder, addition.command)
	}
	slices.Sort(expectedOrder)
	if !slices.Equal(expectedOrder, nextOrder) {
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
