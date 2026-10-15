package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentroute"
	"github.com/research-engineering/agentic-proofkit/internal/command/changeworkflowplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

type agentWorkflowOwnerRow struct {
	command, direction, semantic, wire string
	variants                           [][2]string
	builds                             []func() (map[string]any, error)
}

func plain(build func() map[string]any) func() (map[string]any, error) {
	return func() (map[string]any, error) { return build(), nil }
}

// The variant inventory is copied from the retired root-shape predecessors:
// identical IDs and selection conditions conserve public variant semantics.
func agentWorkflowOwnerRows() []agentWorkflowOwnerRow {
	return []agentWorkflowOwnerRow{
		{"agent-route", "input", "2", "1", [][2]string{{"01-direct", "default JSON mode"}}, []func() (map[string]any, error){plain(agentroute.InputStructure)}},
		{"agent-route", "output", "3", "3", [][2]string{
			{"01-agent-brief", "--agent-envelope=present --agent-envelope-mode=absent|brief; admitted route input"},
			{"02-agent-envelope-full", "--agent-envelope=present --agent-envelope-mode=full; admitted route input"},
			{"03-invalid-input-repair", "--agent-envelope=present; route input or input-pointer admission failed"},
			{"04-routed", "without --agent-envelope; known goal"},
			{"05-unknown-goal", "without --agent-envelope; goal=unknown"},
		}, []func() (map[string]any, error){plain(agentroute.BriefStructure), plain(agentroute.FullEnvelopeStructure), plain(agentenvelope.InvalidInputStructure),
			plain(agentroute.RoutedReportStructure), plain(agentroute.UnknownGoalReportStructure)}},
		{"change-workflow-plan", "input", "1", "1", [][2]string{{"01-root", "default JSON input"}}, []func() (map[string]any, error){plain(changeworkflowplan.InputStructure)}},
		{"change-workflow-plan", "output", "1", "1", [][2]string{
			{"01-agent-envelope", "--agent-envelope"},
			{"02-next-action", "without --agent-envelope; outputKind=next_action; without successorStateDelta"},
			{"03-accept-stage", "without --agent-envelope; outputKind=next_action; successorStateDelta"},
			{"04-workflow-complete", "without --agent-envelope; outputKind=workflow_complete"},
		}, []func() (map[string]any, error){plain(changeworkflowplan.EnvelopeStructure), plain(changeworkflowplan.NextActionOutputStructure),
			plain(changeworkflowplan.AcceptStageOutputStructure), plain(changeworkflowplan.WorkflowCompleteOutputStructure)}},
		{"native-evidence-guidance", "output", "1", "1", [][2]string{{"01-root", "default JSON mode"}}, []func() (map[string]any, error){nativeevidenceguidance.OutputStructure}},
	}
}

func agentWorkflowDefinitionID(row agentWorkflowOwnerRow) string {
	return "proofkit." + row.command + "." + row.direction + ".v" + row.semantic + ".json-schema"
}

func TestAgentWorkflowOwnersConservePublishedIdentityAndVariants(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	contract := readFixtureContract(t, root)
	published := map[string]map[string]any{}
	for _, raw := range contract["contractDefinitions"].([]any) {
		record := raw.(map[string]any)
		published[record["definitionId"].(string)] = record
	}
	for _, row := range agentWorkflowOwnerRows() {
		id := agentWorkflowDefinitionID(row)
		t.Run(id, func(t *testing.T) {
			owner, ok := nativeStructureOwner(id)
			predecessor := "proofkit." + row.command + "." + row.direction + ".v" + row.semantic + ".root-shape"
			if !ok || owner.direction != row.direction || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{predecessor}) {
				t.Fatalf("wrong native owner registration: %s", id)
			}
			if _, retired := published[predecessor]; retired {
				t.Fatalf("predecessor %s remains published", predecessor)
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			version, err := owner.contractVersion(definition)
			if err != nil || version != json.Number(row.wire) || owner.contractID(row.command, version) != "proofkit."+row.command+"."+row.direction+".v"+row.semantic {
				t.Fatalf("semantic/wire identity drift: %s %v", version, err)
			}
			binding := commandAt(contract, row.command)[row.direction+"Contract"].(map[string]any)
			if binding["rootDefinitionRef"] != id || binding["schemaVersion"] != json.Number(row.wire) || binding["contractId"] != "proofkit."+row.command+"."+row.direction+".v"+row.semantic {
				t.Fatalf("published binding identity drift: %v", binding)
			}
			if err := admitNativeStructureDefinition(id, published[id]); err != nil {
				t.Fatal(err)
			}
			variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
			if len(variants) != len(row.variants) || len(row.builds) != len(row.variants) {
				t.Fatalf("variant inventory drift: %d", len(variants))
			}
			for index, raw := range variants {
				variant := raw.(map[string]any)
				if variant["variantId"] != row.variants[index][0] || !reflect.DeepEqual(variant["when"], []any{row.variants[index][1]}) {
					t.Fatalf("variant %d identity or selection drift: %v %v", index, variant["variantId"], variant["when"])
				}
				want, err := row.builds[index]()
				if err != nil || !equalPublishedSchema(variant["schema"], want) {
					t.Fatalf("variant %s is not command-owner derived: %v", row.variants[index][0], err)
				}
			}
			for _, mutation := range []string{"open", "required", "version", "variant"} {
				changed, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				changedVariants := changed["fieldTree"].(map[string]any)["variants"].([]any)
				schema := changedVariants[len(changedVariants)-1].(map[string]any)["schema"].(map[string]any)
				switch mutation {
				case "open":
					schema["additionalProperties"] = true
				case "required":
					schema["required"] = []any{}
				case "version":
					schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("9")
				case "variant":
					changedVariants[0].(map[string]any)["when"] = []any{"foreign condition"}
				}
				delete(changed, "canonicalDigest")
				encoded, err := canonicalJSON(changed)
				if err != nil {
					t.Fatal(err)
				}
				changed["canonicalDigest"] = sha256Digest(encoded)
				if admitNativeStructureDefinition(id, changed) == nil {
					t.Fatalf("accepted coherently rehashed %s drift", mutation)
				}
			}
		})
	}
}

func TestAgentRouteConsumerIdentityRejectsWireOrSemanticDrift(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ direction, mutation, field, value string }{
		{"input", "positive", "", ""},
		{"input", "wire version as semantic", "schemaVersion", "2"},
		{"input", "retired semantic identity", "contractId", "proofkit.agent-route.input.v1"},
		{"output", "variant header as contract", "schemaVersion", "1"},
		{"output", "older contract", "contractId", "proofkit.agent-route.output.v2"},
	} {
		t.Run(row.direction+"/"+row.mutation, func(t *testing.T) {
			value, err := admission.DecodeJSON(bytes.NewReader(source), installedclicontract.MaximumContractBytes)
			if err != nil {
				t.Fatal(err)
			}
			contract := value.(map[string]any)
			definitions, err := admitDefinitions(contract)
			if err != nil {
				t.Fatal(err)
			}
			binding := commandAt(contract, "agent-route")[row.direction+"Contract"].(map[string]any)
			switch row.field {
			case "schemaVersion":
				binding[row.field] = json.Number(row.value)
			case "contractId":
				binding[row.field] = row.value
			}
			err = admitNativeStructureConsumers(contract, definitions)
			if row.mutation == "positive" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "agent-route "+row.direction+" contract violates native semantic contract identity") {
				t.Fatalf("identity drift did not reach the native consumer guard: %v", err)
			}
		})
	}
}

func TestAgentWorkflowEnrichmentRetiresEveryPredecessorAnnotation(t *testing.T) {
	route, ok := nativeStructureOwner("proofkit.agent-route.output.v3.json-schema")
	if !ok {
		t.Fatal("agent-route output owner absent")
	}
	predecessor := route.predecessors[0]
	combined := "nested proofkit.agent-route.brief.v1 contract plus root-shape definition " + predecessor
	notes := []any{"guidanceSlice", "selectedRouteFamily", "schemaVersion=3", "brief agent packet by default with explicit full envelope detail mode", combined}
	got, err := enrichedCompatibilitySummary(route, "3", notes)
	want := append(route.summary("3"), notes[:4]...)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("combined predecessor annotation not retired or independent notes lost: %v %v", got, err)
	}
	for _, stale := range []string{
		"see root-shape definition " + predecessor,
		"nested proofkit.agent-route.brief.v1 contract plus root-shape definition " + predecessor + " and more",
		combined + "; nested fields remain native",
	} {
		if _, err := enrichedCompatibilitySummary(route, "3", []any{"guidanceSlice", stale}); err == nil {
			t.Fatalf("accepted a note that still names the retired definition: %s", stale)
		}
	}
	for _, row := range agentWorkflowOwnerRows() {
		owner, _ := nativeStructureOwner(agentWorkflowDefinitionID(row))
		annotation := "root-shape-only definition " + owner.predecessors[0] + "; nested fields, types, and cardinalities are non-claims"
		got, err := enrichedCompatibilitySummary(owner, json.Number(row.wire), []any{"schemaVersion=" + row.wire, annotation, "Independent caller note."})
		if err != nil || !slices.Contains(got, any("Independent caller note.")) || slices.Contains(got, any(annotation)) {
			t.Fatalf("%s enrichment did not retire its standard annotation: %v %v", row.command, got, err)
		}
	}
}
