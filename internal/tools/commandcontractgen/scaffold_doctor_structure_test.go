package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptiondoctor"
	"github.com/research-engineering/agentic-proofkit/internal/command/projectstructure"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

type scaffoldDoctorOwner struct {
	command, direction, semantic, wire string
	variants                           map[string]string
	schemas                            []func() map[string]any
}

func scaffoldDoctorOwners() map[string]scaffoldDoctorOwner {
	invalid := "--agent-envelope after command admission rejects decoded input; JSON framing and argument errors use stderr"
	return map[string]scaffoldDoctorOwner{
		"proofkit.adoption-doctor.input.v1.json-schema": {"adoption-doctor", "input", "1", "1",
			map[string]string{"01-root": "default JSON mode"}, []func() map[string]any{adoptiondoctor.InputStructure}},
		"proofkit.adoption-doctor.output.v2.json-schema": {"adoption-doctor", "output", "2", "1",
			map[string]string{"01-agent-envelope": "--agent-envelope with admitted input", "02-report": "without --agent-envelope", "03-invalid-input-envelope": invalid},
			[]func() map[string]any{adoptiondoctor.EnvelopeStructure, adoptiondoctor.OutputStructure, agentenvelope.InvalidInputStructure}},
		"proofkit.scaffold-project-structure.input.v2.json-schema": {"scaffold-project-structure", "input", "2", "1",
			map[string]string{"01-root": "default JSON mode"}, []func() map[string]any{projectstructure.InputStructure}},
		"proofkit.scaffold-project-structure.output.v2.json-schema": {"scaffold-project-structure", "output", "2", "1",
			map[string]string{"01-agent-envelope": "--agent-envelope with admitted input", "02-scaffold": "without --agent-envelope", "03-invalid-input-envelope": invalid},
			[]func() map[string]any{projectstructure.EnvelopeStructure, projectstructure.OutputStructure, agentenvelope.InvalidInputStructure}},
		"proofkit.scaffold-profile-plan.input.v1.json-schema": {"scaffold-profile-plan", "input", "1", "1",
			map[string]string{"01-root": "default JSON mode"}, []func() map[string]any{scaffoldprofileplan.InputStructure}},
		"proofkit.scaffold-profile-plan.output.v1.json-schema": {"scaffold-profile-plan", "output", "1", "1",
			map[string]string{"01-plan": "default JSON mode"}, []func() map[string]any{scaffoldprofileplan.OutputStructure}},
	}
}

func TestScaffoldDoctorOwnersConserveIdentityAndRetirePredecessors(t *testing.T) {
	contract := readFixtureContract(t, filepath.Join("..", "..", ".."))
	definitions := map[string]map[string]any{}
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		definitions[definition["definitionId"].(string)] = definition
	}
	for id, want := range scaffoldDoctorOwners() {
		t.Run(id, func(t *testing.T) {
			owner, ok := nativeStructureOwner(id)
			predecessors := []string{"proofkit." + want.command + "." + want.direction + ".v" + want.wire + ".root-shape"}
			if id == "proofkit.scaffold-project-structure.output.v2.json-schema" {
				predecessors = append(predecessors, "proofkit.scaffold-project-structure.output.v1.json-schema")
			}
			if id == "proofkit.adoption-doctor.output.v2.json-schema" {
				predecessors = append(predecessors, "proofkit.adoption-doctor.output.v1.json-schema")
			}
			if !ok || owner.direction != want.direction || !reflect.DeepEqual(owner.commands, []string{want.command}) || !reflect.DeepEqual(owner.predecessors, predecessors) {
				t.Fatal("wrong native owner registration")
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			version, err := owner.contractVersion(definition)
			contractID := "proofkit." + want.command + "." + want.direction + ".v" + want.semantic
			if err != nil || version != json.Number(want.wire) || owner.contractID(want.command, version) != contractID {
				t.Fatalf("semantic/wire identity drift: %s %v", version, err)
			}
			if err := admitNativeStructureDefinition(id, definition); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(definitions[id], normalizedJSON(t, definition)) {
				t.Fatal("published definition is not the native owner projection")
			}
			for _, predecessor := range predecessors {
				if _, stale := definitions[predecessor]; stale {
					t.Fatalf("predecessor %s remains published", predecessor)
				}
			}
			binding := commandAt(contract, want.command)[want.direction+"Contract"].(map[string]any)
			if binding["rootDefinitionRef"] != id || binding["rootDefinitionDigest"] != definition["canonicalDigest"] ||
				binding["contractId"] != contractID || binding["schemaVersion"] != json.Number(want.wire) {
				t.Fatal("consumer binding did not conserve contract identity")
			}
			variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
			if len(variants) != len(want.variants) || len(variants) != len(want.schemas) {
				t.Fatalf("variant partition changed: %d", len(variants))
			}
			for index, raw := range variants {
				variant := raw.(map[string]any)
				when, ok := want.variants[variant["variantId"].(string)]
				if !ok || !reflect.DeepEqual(variant["when"], []any{when}) || !equalPublishedSchema(variant["schema"], want.schemas[index]()) {
					t.Fatalf("variant %v is not its owner-derived selection", variant["variantId"])
				}
			}
			for _, mutation := range []string{"open", "required", "version"} {
				changed, err := owner.definition()
				if err != nil {
					t.Fatal(err)
				}
				schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
				switch mutation {
				case "open":
					schema["additionalProperties"] = true
				case "required":
					schema["required"] = []any{}
				case "version":
					schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("2")
				}
				delete(changed, "canonicalDigest")
				encoded, err := canonicalJSON(changed)
				if err != nil {
					t.Fatal(err)
				}
				changed["canonicalDigest"] = sha256Digest(encoded)
				if admitNativeStructureDefinition(id, changed) == nil {
					t.Fatalf("accepted rehashed %s drift", mutation)
				}
			}
		})
	}
}

func TestScaffoldDoctorSummariesKeepIndependentPolicyNotes(t *testing.T) {
	owner, _ := nativeStructureOwner("proofkit.scaffold-project-structure.input.v2.json-schema")
	note := "Bootstrap rejects secret-shaped keys and values in a detached strict JSON snapshot before decisions or payload emission; wire version is unchanged."
	annotation := "root-shape-only definition proofkit.scaffold-project-structure.input.v1.root-shape; nested fields, types, and cardinalities are non-claims"
	got, err := enrichedCompatibilitySummary(owner, "1", []any{"schemaVersion=1", annotation, note})
	if err != nil || !reflect.DeepEqual(got, append(owner.summary("1"), note)) {
		t.Fatalf("bootstrap safety note lost: %v %v", got, err)
	}
	contract := readFixtureContract(t, filepath.Join("..", "..", ".."))
	summary := commandAt(contract, "scaffold-project-structure")["inputContract"].(map[string]any)["compatibilitySummary"].([]any)
	if !reflect.DeepEqual(summary, got) {
		t.Fatal("published summary differs from enriched owner summary")
	}
	aggregate, _ := nativeStructureOwner("proofkit.scaffold-project-structure.output.v2.json-schema")
	if !strings.HasPrefix(aggregate.summary("1")[0].(string), "contractSchemaVersion=1 (aggregate;") {
		t.Fatal("output variants without a root schemaVersion need aggregate version authority")
	}
}

func TestScaffoldStructureConsumerIdentityRejectsRetiredSemanticVersion(t *testing.T) {
	for _, mutation := range []string{"positive", "retired identity", "wrong wire version", "retired output identity", "output wire version", "future output identity", "retired output schema", "retired output root"} {
		// Independent v2/wire1 bindings exercise admission without depending on
		// the separate published-projection freshness test above.
		command := map[string]any{"command": "scaffold-project-structure"}
		definitions := map[string]definitionRecord{}
		for _, direction := range []string{"input", "output"} {
			contractID := "proofkit.scaffold-project-structure." + direction + ".v2"
			id := contractID + ".json-schema"
			owner, ok := nativeStructureOwner(id)
			if !ok {
				t.Fatalf("missing owner %s", id)
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			definitions[id] = definitionRecord{ID: id, Content: definition}
			command[direction+"Contract"] = map[string]any{"contractId": contractID, "schemaVersion": json.Number("1"), "rootDefinitionRef": id}
		}
		contract := map[string]any{"commands": []any{command}}
		want := "scaffold-project-structure input contract violates native semantic contract identity"
		switch mutation {
		case "retired identity":
			command["inputContract"].(map[string]any)["contractId"] = "proofkit.scaffold-project-structure.input.v1"
		case "wrong wire version":
			command["inputContract"].(map[string]any)["schemaVersion"] = json.Number("2")
		case "retired output identity":
			command["outputContract"].(map[string]any)["contractId"] = "proofkit.scaffold-project-structure.output.v1"
			want = "scaffold-project-structure output contract violates native semantic contract identity"
		case "output wire version":
			command["outputContract"].(map[string]any)["schemaVersion"] = json.Number("2")
			want = "scaffold-project-structure output contract violates native semantic contract identity"
		case "future output identity":
			command["outputContract"].(map[string]any)["contractId"] = "proofkit.scaffold-project-structure.output.v3"
			want = "scaffold-project-structure output contract violates native semantic contract identity"
		case "retired output schema", "retired output root":
			id := "proofkit.scaffold-project-structure.output.v1.json-schema"
			if mutation == "retired output root" {
				id = "proofkit.scaffold-project-structure.output.v1.root-shape"
			}
			definitions[id] = definitionRecord{ID: id}
			want = "obsolete native structure " + id + " remains"
		}
		err := admitNativeStructureConsumers(contract, definitions)
		if mutation == "positive" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s did not reach the exact native consumer guard: %v", mutation, err)
		}
	}
}

func TestScaffoldStructureOutputRejectsRehashedBlockerDrift(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.scaffold-project-structure.output.v2.json-schema")
	if !ok || owner.semanticVersion != 2 || owner.aggregateVersion != "1" {
		t.Fatal("scaffold output must have semantic v2 and aggregate wire1")
	}
	for _, mutation := range []string{"positive", "retired blocker field", "input repair for scalar blocker"} {
		changed := owner
		changed.variants = append([]nativeStructureVariant{}, owner.variants...)
		changed.variants[1].schema = func() (map[string]any, error) {
			schema := projectstructure.OutputStructure()
			workflow := schema["properties"].(map[string]any)["adoptionWorkflowPlan"].(map[string]any)
			blocker := workflow["properties"].(map[string]any)["blockers"].(map[string]any)["items"].(map[string]any)
			properties := blocker["properties"].(map[string]any)
			if !reflect.DeepEqual(properties["inputAlternatives"], map[string]any{"type": "array", "items": false, "minItems": 0, "maxItems": 0}) {
				t.Fatal("all bundled refs are supplied; only an empty scalar-preset repair is reachable")
			}
			switch mutation {
			case "retired blocker field":
				delete(properties, "inputAlternatives")
				properties["requiredInputKinds"] = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
				blocker["required"] = []any{"blockerId", "nonClaim", "reason", "requiredInputKinds", "scenario"}
			case "input repair for scalar blocker":
				properties["inputAlternatives"] = map[string]any{"type": "array", "items": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}
			}
			return schema, nil
		}
		definition, err := changed.definition()
		if err != nil {
			t.Fatal(err)
		}
		if err := admitNativeStructureDefinition(owner.id, definition); (err == nil) != (mutation == "positive") {
			t.Fatalf("%s: rehashed embedded blocker admission=%v", mutation, err)
		}
	}
}

func normalizedJSON(t *testing.T, value any) any {
	t.Helper()
	encoded, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), installedclicontract.MaximumContractBytes)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
