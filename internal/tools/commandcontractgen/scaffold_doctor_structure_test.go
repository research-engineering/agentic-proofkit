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
		"proofkit.adoption-doctor.output.v1.json-schema": {"adoption-doctor", "output", "1", "1",
			map[string]string{"01-agent-envelope": "--agent-envelope with admitted input", "02-report": "without --agent-envelope", "03-invalid-input-envelope": invalid},
			[]func() map[string]any{adoptiondoctor.EnvelopeStructure, adoptiondoctor.OutputStructure, agentenvelope.InvalidInputStructure}},
		"proofkit.scaffold-project-structure.input.v2.json-schema": {"scaffold-project-structure", "input", "2", "1",
			map[string]string{"01-root": "default JSON mode"}, []func() map[string]any{projectstructure.InputStructure}},
		"proofkit.scaffold-project-structure.output.v1.json-schema": {"scaffold-project-structure", "output", "1", "1",
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
			predecessor := "proofkit." + want.command + "." + want.direction + ".v" + want.wire + ".root-shape"
			if !ok || owner.direction != want.direction || !reflect.DeepEqual(owner.commands, []string{want.command}) || !reflect.DeepEqual(owner.predecessors, []string{predecessor}) {
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
			if _, stale := definitions[predecessor]; stale {
				t.Fatal("root-shape predecessor remains published")
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
	aggregate, _ := nativeStructureOwner("proofkit.scaffold-project-structure.output.v1.json-schema")
	if !strings.HasPrefix(aggregate.summary("1")[0].(string), "contractSchemaVersion=1 (aggregate;") {
		t.Fatal("output variants without a root schemaVersion need aggregate version authority")
	}
}

func TestScaffoldStructureConsumerIdentityRejectsRetiredSemanticVersion(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := readContract(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"positive", "retired identity", "wrong wire version", "output version"} {
		value, err := admission.DecodeJSON(bytes.NewReader(source), installedclicontract.MaximumContractBytes)
		if err != nil {
			t.Fatal(err)
		}
		contract := value.(map[string]any)
		definitions, err := admitDefinitions(contract)
		if err != nil {
			t.Fatal(err)
		}
		command := commandAt(contract, "scaffold-project-structure")
		want := "scaffold-project-structure input contract violates native semantic contract identity"
		switch mutation {
		case "retired identity":
			command["inputContract"].(map[string]any)["contractId"] = "proofkit.scaffold-project-structure.input.v1"
		case "wrong wire version":
			command["inputContract"].(map[string]any)["schemaVersion"] = json.Number("2")
		case "output version":
			command["outputContract"].(map[string]any)["contractId"] = "proofkit.scaffold-project-structure.output.v2"
			want = "scaffold-project-structure output contract violates native semantic contract identity"
		}
		err = admitNativeStructureConsumers(contract, definitions)
		if mutation == "positive" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s did not reach the exact native consumer guard: %v", mutation, err)
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
