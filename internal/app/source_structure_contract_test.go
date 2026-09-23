package app

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementauthoringplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const sourceStructureDefinition = "proofkit.requirement-source.input.v2.json-schema"
const sourceOutputStructureDefinition = "proofkit.requirement-source-admission.output.v2.json-schema"
const sourceViewOutputStructureDefinition = "proofkit.requirement-source-view.output.v2.json-schema"
const transitionInputStructureDefinition = "proofkit.requirement-source-transition.input.v2.json-schema"
const transitionOutputStructureDefinition = "proofkit.requirement-source-transition.output.v2.json-schema"
const authoringInputStructureDefinition = "proofkit.requirement-authoring-plan.input.v2.json-schema"
const authoringOutputStructureDefinition = "proofkit.requirement-authoring-plan.output.v3.json-schema"
const contextCatalogStructureDefinition = "proofkit.requirement-context-compose.input.v2.json-schema"
const specTreeStructureDefinition = "proofkit.requirement-spec-tree.input.v2.json-schema"

func TestSourceCoverageOutputStructuralContractMatchesNativeOwner(t *testing.T) {
	contract := readCLIContractRaw(t)
	definitions, _, err := indexPublicABIRecords(contract["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	const id = "proofkit.requirement-coverage-view.output.v4.json-schema"
	definition := definitions[id]
	if definition == nil {
		t.Fatal("coverage output structure is not shipped")
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if len(variants) != 2 || variants[1].(map[string]any)["variantId"] != "02-report" ||
		!reflect.DeepEqual(canonicalJSONValue(t, variants[1].(map[string]any)["schema"]), canonicalJSONValue(t, requirementcoverageview.OutputStructure())) {
		t.Fatal("coverage report schema differs from its native owner")
	}
	commands, _, err := indexPublicABIRecords(contract["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	output := commands["requirement-coverage-view"]["outputContract"].(map[string]any)
	if output["rootDefinitionRef"] != id || output["rootDefinitionDigest"] != definition["canonicalDigest"] || output["schemaVersion"] != json.Number("4") {
		t.Fatal("coverage output identity is not bound to the admitted variants")
	}
}

func TestSourceSnapshotConsumerStructuralContractsMatchNativeOwners(t *testing.T) {
	assertSourceStructure(t, "requirement-context-slice", "input", "proofkit.requirement-context-slice.input.v2.json-schema", requirementcontext.SliceInputStructure())
	assertSourceStructure(t, "requirement-context-slice", "output", "proofkit.requirement-context-slice.output.v2.json-schema", requirementcontext.SliceOutputStructure())
	assertSourceStructure(t, "requirement-semantic-diff", "input", "proofkit.requirement-semantic-diff.input.v3.json-schema", requirementdiff.InputStructure())
	assertSourceStructure(t, "requirement-semantic-diff", "output", "proofkit.requirement-semantic-diff.output.v3.json-schema", requirementdiff.OutputStructure())
	assertSourceStructure(t, "requirement-traceability-graph", "input", "proofkit.requirement-traceability-graph.input.v3.json-schema", requirementgraph.InputStructure())
}

func TestSourceTreeStructuralContractMatchesNativeOwners(t *testing.T) {
	assertNativeStructure(t, "input", specTreeStructureDefinition, requirementspectree.InputStructure(), []string{"requirement-spec-tree", "requirement-spec-tree-view"})
}

func TestSourceContextCatalogStructuralContractMatchesNativeOwner(t *testing.T) {
	assertSourceStructure(t, "requirement-context-compose", "input", contextCatalogStructureDefinition, requirementcontext.CatalogInputStructure())
	assertSourceStructure(t, "requirement-context-compose", "output", "proofkit.requirement-context-compose.output.v4.json-schema", requirementcontext.CatalogSnapshotStructure())
}

func TestSourceOutputStructuralContractMatchesNativeOwner(t *testing.T) {
	assertSourceOutputStructure(t, "requirement-source-admission", sourceOutputStructureDefinition, requirementsourceadmission.OutputStructure())
}

func TestSourceViewOutputStructuralContractMatchesNativeOwner(t *testing.T) {
	assertSourceOutputStructure(t, "requirement-source-view", sourceViewOutputStructureDefinition, requirementsourceview.OutputStructure())
}

func TestSourceTransitionStructuralContractsMatchNativeOwner(t *testing.T) {
	assertSourceStructure(t, "requirement-source-transition", "input", transitionInputStructureDefinition, requirementsourcetransition.InputStructure())
	assertSourceStructure(t, "requirement-source-transition", "output", transitionOutputStructureDefinition, requirementsourcetransition.OutputStructure())
}

func TestSourceAuthoringStructuralContractsMatchNativeOwner(t *testing.T) {
	assertSourceStructure(t, "requirement-authoring-plan", "input", authoringInputStructureDefinition, requirementauthoringplan.InputStructure())
	assertSourceStructure(t, "requirement-authoring-plan", "output", authoringOutputStructureDefinition, requirementauthoringplan.OutputStructure())
}

func assertSourceOutputStructure(t *testing.T, commandName, definitionID string, expected map[string]any) {
	t.Helper()
	assertSourceStructure(t, commandName, "output", definitionID, expected)
}

func assertSourceStructure(t *testing.T, commandName, wantedDirection, definitionID string, expected map[string]any) {
	t.Helper()
	assertNativeStructure(t, wantedDirection, definitionID, expected, []string{commandName})
}

func assertNativeStructure(t *testing.T, wantedDirection, definitionID string, expected map[string]any, commands []string) {
	t.Helper()
	root := expected
	if alternatives, ok := expected["oneOf"].([]any); ok && expected["type"] == nil {
		root = alternatives[0].(map[string]any)
	}
	version := root["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"].(json.Number)
	contract := readCLIContractRaw(t)
	definitions, _, err := indexPublicABIRecords(contract["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	definition := definitions[definitionID]
	if definition == nil {
		t.Fatal("source output structure is not shipped")
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if len(variants) != 1 || !reflect.DeepEqual(canonicalJSONValue(t, variants[0].(map[string]any)["schema"]), canonicalJSONValue(t, expected)) {
		t.Fatal("source output schema differs from its native owner")
	}
	consumers := []string{}
	for _, raw := range contract["commands"].([]any) {
		command := raw.(map[string]any)
		for _, direction := range []string{"input", "output"} {
			binding, _ := command[direction+"Contract"].(map[string]any)
			if binding["rootDefinitionRef"] != definitionID {
				continue
			}
			consumers = append(consumers, command["command"].(string)+" "+direction)
			if binding["contractId"] != "proofkit."+command["command"].(string)+"."+wantedDirection+".v"+version.String() || binding["schemaVersion"] != version || binding["rootDefinitionDigest"] != definition["canonicalDigest"] {
				t.Fatal("output identity or digest is not bound to its native schema")
			}
		}
	}
	wantConsumers := make([]string, len(commands))
	for i, name := range commands {
		wantConsumers[i] = name + " " + wantedDirection
	}
	if !reflect.DeepEqual(consumers, wantConsumers) {
		t.Fatalf("unexpected output schema consumers: %v", consumers)
	}
}

func TestSourceStructuralContractMatchesNativeOwnerAndConsumerIdentities(t *testing.T) {
	contract := readCLIContractRaw(t)
	definitions, _, err := indexPublicABIRecords(contract["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	definition := definitions[sourceStructureDefinition]
	if definition == nil {
		t.Fatal("public source structural definition is missing")
	}
	want, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if len(variants) != 1 || !reflect.DeepEqual(canonicalJSONValue(t, variants[0].(map[string]any)["schema"]), canonicalJSONValue(t, want)) {
		t.Fatal("shipped source schema differs from the complete native structural projection")
	}
	consumers := []string{}
	for _, raw := range contract["commands"].([]any) {
		command := raw.(map[string]any)
		name := command["command"].(string)
		for _, direction := range []string{"input", "output"} {
			binding, _ := command[direction+"Contract"].(map[string]any)
			if binding["rootDefinitionRef"] != sourceStructureDefinition {
				continue
			}
			consumers = append(consumers, name+" "+direction)
			if binding["contractId"] != "proofkit."+name+".input.v2" || binding["schemaVersion"] != json.Number("2") || binding["rootDefinitionDigest"] != definition["canonicalDigest"] {
				t.Fatal("source consumer retained an obsolete or unbound contract identity")
			}
		}
	}
	if !reflect.DeepEqual(consumers, []string{"requirement-source-admission input", "requirement-source-view input"}) {
		t.Fatalf("source structural consumer set=%v", consumers)
	}
	for _, old := range []string{"proofkit.requirement-source-admission.input.v1.root-shape", "proofkit.requirement-source-view.input.v1.root-shape"} {
		if definitions[old] != nil {
			t.Fatal("obsolete flat source definition remains public")
		}
	}
}
