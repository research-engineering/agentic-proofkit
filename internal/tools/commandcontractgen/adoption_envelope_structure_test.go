package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptioncontract"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission"
)

type adoptionEnvelopeOwner struct {
	id, command, wire, contractID, rootType string
	predecessor                             string
	variants                                map[string]func() map[string]any
	conditions                              map[string][]string
}

// Independently restated identities: the published contract IDs and wire
// versions existed before these owners and must survive the cutover.
func adoptionEnvelopeOwners() []adoptionEnvelopeOwner {
	report := pilotadmission.ReportStructure
	guidance := func(mode, scope, touched bool) func() map[string]any {
		return func() map[string]any { return adoptioncontract.GuidanceInputStructure(mode, scope, touched) }
	}
	pilot := func(variant string) func() map[string]any {
		return func() map[string]any { return adoptioncontract.PilotInputStructure(variant) }
	}
	agent := func(mode string) func() map[string]any {
		return func() map[string]any { return adoptioncontract.AgentOutputStructure(mode) }
	}
	contract := func(fields ...string) func() map[string]any {
		return func() map[string]any { return pilotadmission.ContractInputStructure(fields...) }
	}
	return []adoptionEnvelopeOwner{{
		id: "proofkit.adoption-contract-envelope.input.v3.json-schema", command: "adoption-contract-envelope", wire: "2",
		contractID: "proofkit.adoption-contract-envelope.input.v3", rootType: "object", predecessor: "proofkit.adoption-contract-envelope.input.v2.root-shape",
		variants: map[string]func() map[string]any{
			"01-adoption": adoptioncontract.AdoptionInputStructure, "02-bootstrap": adoptioncontract.BootstrapInputStructure,
			"03-guidance-000": guidance(false, false, false), "04-guidance-001": guidance(true, false, false),
			"05-guidance-010": guidance(false, true, false), "06-guidance-011": guidance(true, true, false),
			"07-guidance-100": guidance(false, false, true), "08-guidance-101": guidance(true, false, true),
			"09-guidance-110": guidance(false, true, true), "10-guidance-111": guidance(true, true, true),
			"11-pilot-all": pilot("all"), "12-pilot-first": pilot("first"), "13-pilot-stack-diverse": pilot("stack-diverse"),
			"14-workflow": adoptioncontract.WorkflowInputStructure,
		},
		conditions: map[string][]string{
			"12-pilot-first": {"--mode pilot --pilot first", "--mode pilot without --pilot (defaults first)"},
		},
	}, {
		id: "proofkit.adoption-contract-envelope.output.v1.json-schema", command: "adoption-contract-envelope", wire: "1",
		contractID: "proofkit.adoption-contract-envelope.output.v1", rootType: "union", predecessor: "proofkit.adoption-contract-envelope.output.v1.root-shape",
		variants: map[string]func() map[string]any{
			"01-adoption-report": gradualadoption.OutputStructure, "02-bootstrap": gradualadoption.BootstrapOutputStructure,
			"03-bootstrap-agent": agent("bootstrap"), "04-bootstrap-materialization": gradualadoption.BootstrapMaterializationStructure,
			"05-guidance-agent": agent("guidance"), "06-guidance-report": gradualadoption.GuidanceOutputStructure,
			"07-pilot-all": pilotadmission.AllOutputStructure, "08-pilot-first": report, "09-pilot-stack-diverse": report,
			"10-workflow-agent": agent("workflow"), "11-workflow-plan": adoptionworkflow.OutputStructure,
		},
		conditions: map[string][]string{
			"08-pilot-first": {
				"--agent-envelope=absent --materialization-manifest=absent --mode=pilot --pilot=absent",
				"--agent-envelope=absent --materialization-manifest=absent --mode=pilot --pilot=first",
			},
		},
	}, {
		id: "proofkit.adoption-workflow-plan.input.v1.json-schema", command: "adoption-workflow-plan", wire: "1",
		contractID: "proofkit.adoption-workflow-plan.input.v1", rootType: "object", predecessor: "proofkit.adoption-workflow-plan.input.v1.root-shape",
		variants: map[string]func() map[string]any{"01-contract-envelope": adoptionworkflow.ContractInputStructure, "02-direct": adoptionworkflow.InputStructure},
	}, {
		id: "proofkit.adoption-workflow-plan.output.v1.json-schema", command: "adoption-workflow-plan", wire: "1",
		contractID: "proofkit.adoption-workflow-plan.output.v1", rootType: "object", predecessor: "proofkit.adoption-workflow-plan.output.v1.root-shape",
		variants: map[string]func() map[string]any{"01-agent-envelope": adoptionworkflow.EnvelopeOutputStructure, "02-workflow-plan": adoptionworkflow.OutputStructure},
	}, {
		id: "proofkit.pilot-admission.input.v2.json-schema", command: "pilot-admission", wire: "2",
		contractID: "proofkit.pilot-admission.input.v2", rootType: "object", predecessor: "proofkit.pilot-admission.input.v2.root-shape",
		variants: map[string]func() map[string]any{
			"01-contract-all": contract("input", "stackDiverseInput"), "02-contract-first": contract("input"),
			"03-contract-stack-diverse": contract("stackDiverseInput"), "04-direct": pilotadmission.InputStructure,
		},
		conditions: map[string][]string{
			"04-direct": {
				"without --contract-envelope; --pilot first", "without --contract-envelope; without --pilot (defaults first)",
				"without --contract-envelope; --pilot stack-diverse", "without --contract-envelope; --stack-diverse",
			},
		},
	}, {
		id: "proofkit.pilot-admission.output.v1.json-schema", command: "pilot-admission", wire: "1",
		contractID: "proofkit.pilot-admission.output.v1", rootType: "union", predecessor: "proofkit.pilot-admission.output.v1.root-shape",
		variants: map[string]func() map[string]any{"01-all": pilotadmission.AllOutputStructure, "02-report": report},
	}}
}

func TestAdoptionEnvelopeOwnersConserveIdentityAndBindExactVariants(t *testing.T) {
	contract := readFixtureContract(t, filepath.Join("..", "..", ".."))
	published := map[string]map[string]any{}
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		published[definition["definitionId"].(string)] = definition
	}
	for _, expected := range adoptionEnvelopeOwners() {
		owner, exists := nativeStructureOwner(expected.id)
		if !exists || !slices.Equal(owner.commands, []string{expected.command}) {
			t.Fatalf("missing or widened owner %s", expected.id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		wire, err := owner.contractVersion(definition)
		if err != nil || wire != json.Number(expected.wire) || owner.contractID(expected.command, wire) != expected.contractID {
			t.Fatalf("%s identity drifted: wire=%s id=%s err=%v", expected.id, wire, owner.contractID(expected.command, wire), err)
		}
		if err := admitNativeStructureDefinition(expected.id, definition); err != nil {
			t.Fatal(err)
		}
		if _, stale := published[expected.predecessor]; stale {
			t.Fatalf("predecessor %s is still published", expected.predecessor)
		}
		binding := commandAt(contract, expected.command)[owner.direction+"Contract"].(map[string]any)
		if binding["rootDefinitionRef"] != expected.id || binding["contractId"] != expected.contractID ||
			binding["schemaVersion"] != json.Number(expected.wire) || binding["rootType"] != expected.rootType || definition["rootType"] != expected.rootType {
			t.Fatalf("%s consumer binding drifted: %v", expected.id, binding)
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		if len(variants) != len(expected.variants) {
			t.Fatalf("%s has %d variants want %d", expected.id, len(variants), len(expected.variants))
		}
		for _, raw := range variants {
			variant := raw.(map[string]any)
			id := variant["variantId"].(string)
			build, known := expected.variants[id]
			if !known || !equalPublishedSchema(variant["schema"], build()) {
				t.Fatalf("%s variant %s is not its native owner projection", expected.id, id)
			}
			if want, multiple := expected.conditions[id]; multiple && !reflect.DeepEqual(adoptionEnvelopeStrings(variant["when"]), want) {
				t.Fatalf("%s variant %s conditions=%v want %v", expected.id, id, variant["when"], want)
			}
			if (variant["rootKind"] == "array") != (id == "01-all" || id == "07-pilot-all") {
				t.Fatalf("%s variant %s has root kind %v", expected.id, id, variant["rootKind"])
			}
		}
	}
}

func TestAdoptionEnvelopeConditionModelMovesToTheStructuralOwner(t *testing.T) {
	owner, _ := nativeStructureOwner(cliFlagConditionModelDefinitionID)
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	tree := definition["fieldTree"].(map[string]any)
	if tree["conditionModel"] != "cli_flag_conjunction_v1" || len(tree["variants"].([]any)) != 11 {
		t.Fatal("aggregate output lost its closed flag-condition model")
	}
	conditions := 0
	for _, raw := range tree["variants"].([]any) {
		conditions += len(raw.(map[string]any)["when"].([]any))
	}
	if conditions != 12 {
		t.Fatalf("aggregate output condition cases=%d want 12", conditions)
	}
	for name, mutate := range map[string]func(*nativeStructure){
		"wrong-owner": func(o *nativeStructure) { o.id = "proofkit.adoption-contract-envelope.output.v2.json-schema" },
		"unknown":     func(o *nativeStructure) { o.conditionModel = "free_text" },
		"overlap": func(o *nativeStructure) {
			o.variants = slices.Clone(o.variants)
			o.variants[1].when = o.variants[0].when + " "
		},
		"duplicate": func(o *nativeStructure) {
			o.variants = slices.Clone(o.variants)
			o.variants[1].also = []string{o.variants[0].when}
		},
		"dimension": func(o *nativeStructure) {
			o.variants = slices.Clone(o.variants)
			o.variants[1].when = "--mode=bootstrap"
		},
	} {
		mutant := owner
		mutate(&mutant)
		if _, err := mutant.definition(); err == nil {
			t.Fatalf("%s: condition model drift accepted", name)
		}
	}
}

func TestArrayAndSumRootsRemainOwnerBounded(t *testing.T) {
	pilot, _ := nativeStructureOwner("proofkit.pilot-admission.output.v1.json-schema")
	workflow, _ := nativeStructureOwner("proofkit.adoption-workflow-plan.output.v1.json-schema")
	input, _ := nativeStructureOwner("proofkit.pilot-admission.input.v2.json-schema")
	for name, mutant := range map[string]nativeStructure{
		"array-input": func() nativeStructure {
			owner := input
			owner.variants = slices.Clone(owner.variants)
			owner.variants[0].array = true
			return owner
		}(),
		"array-without-aggregate": func() nativeStructure {
			owner := workflow
			owner.variants = slices.Clone(owner.variants)
			owner.variants[1] = nativeStructureVariant{id: "02-all", when: "array", array: true, schema: func() (map[string]any, error) { return pilotadmission.AllOutputStructure(), nil }}
			return owner
		}(),
		"array-open-items": func() nativeStructure {
			owner := pilot
			owner.variants = slices.Clone(owner.variants)
			owner.variants[0].schema = func() (map[string]any, error) {
				schema := pilotadmission.AllOutputStructure()
				delete(schema, "items")
				return schema, nil
			}
			return owner
		}(),
		"array-only": func() nativeStructure {
			owner := pilot
			owner.variants = slices.Clone(owner.variants)
			owner.variants[1].array, owner.variants[1].schema = true, owner.variants[0].schema
			return owner
		}(),
		"sum-root-drift": func() nativeStructure {
			owner, _ := nativeStructureOwner(cliFlagConditionModelDefinitionID)
			owner.variants = slices.Clone(owner.variants)
			owner.variants[2].schema = func() (map[string]any, error) {
				schema := adoptioncontract.AgentOutputStructure("bootstrap")
				delete(schema["oneOf"].([]any)[1].(map[string]any)["properties"].(map[string]any), "omitted")
				return schema, nil
			}
			return owner
		}(),
		"sum-root-annotation": func() nativeStructure {
			owner, _ := nativeStructureOwner(cliFlagConditionModelDefinitionID)
			owner.variants = slices.Clone(owner.variants)
			owner.variants[2].schema = func() (map[string]any, error) {
				schema := adoptioncontract.AgentOutputStructure("bootstrap")
				schema["type"] = "object"
				return schema, nil
			}
			return owner
		}(),
	} {
		if _, err := mutant.definition(); err == nil {
			t.Fatalf("%s: unbounded root accepted", name)
		}
	}
}

func TestAdoptionEnvelopeDefinitionsRejectRehashedNestedDrift(t *testing.T) {
	for _, expected := range adoptionEnvelopeOwners() {
		owner, _ := nativeStructureOwner(expected.id)
		row, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		variant := row["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
		encoded, err := canonicalJSON(variant["schema"])
		if err != nil {
			t.Fatal(err)
		}
		// Weaken one closed record anywhere in the first variant.
		weakened := strings.Replace(string(encoded), `"additionalProperties":false`, `"additionalProperties":true`, 1)
		var schema any
		decoder := json.NewDecoder(strings.NewReader(weakened))
		decoder.UseNumber()
		if weakened == string(encoded) || decoder.Decode(&schema) != nil {
			t.Fatalf("%s first variant has no closed record", expected.id)
		}
		variant["schema"] = schema
		delete(row, "canonicalDigest")
		digestSource, err := canonicalJSON(row)
		if err != nil {
			t.Fatal(err)
		}
		row["canonicalDigest"] = sha256Digest(digestSource)
		if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{row}}); err == nil {
			t.Fatalf("%s: rehashed nested drift accepted", expected.id)
		}
	}
}

func adoptionEnvelopeStrings(raw any) []string {
	result := []string{}
	for _, value := range raw.([]any) {
		result = append(result, value.(string))
	}
	return result
}
