package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/conformanceprofile"
	"github.com/research-engineering/agentic-proofkit/internal/command/migrationplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceregistry"
)

type profileRegistryOwnerRow struct {
	command, direction, version string
	aggregate                   bool
	variants                    []string
	schemas                     []func() map[string]any
}

func profileRegistryOwnerRows() []profileRegistryOwnerRow {
	return []profileRegistryOwnerRow{
		{"conformance-profile", "input", "2", false, []string{"01-root"}, []func() map[string]any{conformanceprofile.InputStructure}},
		{"conformance-profile", "output", "2", true, []string{"01-list", "02-profile", "03-verify"}, []func() map[string]any{
			conformanceprofile.ListOutputStructure, conformanceprofile.ProfileOutputStructure, conformanceprofile.VerifyOutputStructure}},
		{"migration-plan", "input", "1", false, []string{"01-root"}, []func() map[string]any{migrationplan.InputStructure}},
		{"migration-plan", "output", "1", false, []string{"01-root"}, []func() map[string]any{migrationplan.OutputStructure}},
		{"workspace-registry", "input", "1", false, []string{"01-root"}, []func() map[string]any{workspaceregistry.InputStructure}},
		{"workspace-registry", "output", "1", false, []string{"01-root"}, []func() map[string]any{workspaceregistry.OutputStructure}},
	}
}

func TestProfileRegistryStructuresConservePublishedIdentity(t *testing.T) {
	contract := readFixtureContract(t, filepath.Join("..", "..", ".."))
	published := map[string]map[string]any{}
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		published[definition["definitionId"].(string)] = definition
	}
	for _, row := range profileRegistryOwnerRows() {
		identity := "proofkit." + row.command + "." + row.direction + ".v" + row.version
		id, predecessor := identity+".json-schema", identity+".root-shape"
		owner, ok := nativeStructureOwner(id)
		if !ok || owner.direction != row.direction || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{predecessor}) {
			t.Fatalf("wrong native owner registration: %s", id)
		}
		if (owner.aggregateVersion != "") != row.aggregate || owner.semanticVersion != 0 || owner.wireVersion != "" || owner.outOfBandVersion != "" || owner.optionalInputVersion || owner.jsonValueInput {
			t.Fatalf("unexpected version mode: %s", id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number(row.version) || owner.contractID(row.command, version) != identity {
			t.Fatalf("contract identity drifted: %s %s %v", id, version, err)
		}
		if err := admitNativeStructureDefinition(id, published[id]); err != nil {
			t.Fatal(err)
		}
		if _, stale := published[predecessor]; stale {
			t.Fatalf("predecessor %s remains published", predecessor)
		}
		binding := commandAt(contract, row.command)[row.direction+"Contract"].(map[string]any)
		if binding["rootDefinitionRef"] != id || binding["rootDefinitionDigest"] != definition["canonicalDigest"] ||
			binding["contractId"] != identity || binding["schemaVersion"] != json.Number(row.version) {
			t.Fatalf("%s %s binding lost its published identity", row.command, row.direction)
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		if len(variants) != len(row.variants) {
			t.Fatalf("%s variant partition changed", id)
		}
		for index, raw := range variants {
			variant := raw.(map[string]any)
			if variant["variantId"] != row.variants[index] || !equalPublishedSchema(variant["schema"], row.schemas[index]()) {
				t.Fatalf("%s variant %d is not owner derived", id, index)
			}
		}
		for _, mutation := range []string{"open", "required", "description"} {
			changed, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			schema := changed["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
			if branches, sum := schema["oneOf"].([]any); sum {
				schema = branches[0].(map[string]any)
			}
			switch mutation {
			case "open":
				schema["additionalProperties"] = true
			case "required":
				schema["required"] = []any{}
			case "description":
				schema["description"] = "Foreign description."
			}
			delete(changed, "canonicalDigest")
			encoded, err := canonicalJSON(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed["canonicalDigest"] = sha256Digest(encoded)
			if admitNativeStructureDefinition(id, changed) == nil {
				t.Fatalf("accepted rehashed %s/%s drift", id, mutation)
			}
		}
		annotation := "root-shape-only definition " + predecessor + "; nested fields, types, and cardinalities are non-claims"
		policy := "Preserve this independent caller note."
		header := []any{"schemaVersion=" + row.version}
		if row.aggregate {
			header = []any{owner.summary(json.Number(row.version))[0]}
		}
		got, err := enrichedCompatibilitySummary(owner, json.Number(row.version), append(header, annotation, policy))
		if err != nil || !reflect.DeepEqual(got, append(owner.summary(json.Number(row.version)), policy)) {
			t.Fatalf("owned annotation or independent note lost: %s %v", id, got)
		}
	}
}

func TestProfileRegistryVariantConditionsKeepNativeModePartition(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.conformance-profile.output.v2.json-schema")
	if !ok {
		t.Fatal("conformance output owner missing")
	}
	want := []string{"--list", "--profile <id> with --format json or without --format (defaults json)", "--verify"}
	for index, variant := range owner.variants {
		if variant.when != want[index] {
			t.Fatalf("variant %s condition=%q", variant.id, variant.when)
		}
	}
	// The aggregate contract version is not a list header; only two variants carry wire versions.
	for index, version := range []string{"", "2", "1"} {
		schema, err := owner.variants[index].schema()
		if err != nil {
			t.Fatal(err)
		}
		field, present := schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)
		if present != (version != "") || present && field["const"] != json.Number(version) {
			t.Fatalf("variant %s wire header drifted", owner.variants[index].id)
		}
	}
}
