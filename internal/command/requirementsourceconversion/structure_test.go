package requirementsourceconversion

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// Both emitted documents admit under the published structures, and one
// same-shape mutant per structural clause is rejected by the same owner.
func TestEmissionsConformToPublishedStructures(t *testing.T) {
	flat, err := ExportFlat(fixture(t, "source.grouped.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flatShape.Admit(clone(t, flat), "flat emission"); err != nil {
		t.Fatal(err)
	}
	grouped, err := ImportFlat(clone(t, flat), fixture(t, "source.grouped.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groupedShape.Admit(clone(t, grouped), "grouped emission"); err != nil {
		t.Fatal(err)
	}
	flatMutants := map[string]func(map[string]any){
		"surplus root field":  func(value map[string]any) { value["layout"] = "grouped" },
		"missing coordinates": func(value map[string]any) { delete(value, "groups") },
		"record field gap": func(value map[string]any) {
			delete(at(t, value, "/requirements/0/fields").(map[string]any), "lifecycle")
		},
		"textual stem bytes": func(value map[string]any) { set(t, value, "/groups/1/statementStemBytes", "16") },
		"wrong flat kind":    func(value map[string]any) { value["kind"] = requirementsourcecodec.DocumentKind },
	}
	for name, mutate := range flatMutants {
		mutant := clone(t, flat)
		mutate(mutant)
		if _, err := flatShape.Admit(mutant, "flat mutant"); err == nil {
			t.Fatalf("flat structure admitted %s", name)
		}
	}
	groupedMutants := map[string]func(map[string]any){
		"flat coordinates in grouped": func(value map[string]any) { value["requirements"] = values() },
		"missing members":             func(value map[string]any) { delete(at(t, value, "/groups/0").(map[string]any), "members") },
		"wrong grouped version":       func(value map[string]any) { value["schemaVersion"] = jsonNumber(1) },
	}
	for name, mutate := range groupedMutants {
		mutant := clone(t, grouped)
		mutate(mutant)
		if _, err := groupedShape.Admit(mutant, "grouped mutant"); err == nil {
			t.Fatalf("grouped structure admitted %s", name)
		}
	}
}

// The grouped structure is the codec's own descriptor, and every flat
// collection bound is the model bound of the collection it transcodes to.
func TestPublishedStructuresReuseTheirOwners(t *testing.T) {
	limits := requirementsourcemodel.DefaultLimits()
	codec, err := requirementsourcecodec.InputStructure(limits)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(GroupedStructure(), codec) {
		t.Fatal("grouped structure is not the codec descriptor")
	}
	schema := FlatStructure()
	required := []string{}
	for _, name := range schema["required"].([]any) {
		required = append(required, name.(string))
	}
	slices.Sort(required)
	want := []string{"basisDigest", "derivations", "groups", "kind", "nonClaimDefinitions", "profiles", "requirements", "scenarios", "schemaVersion", "sourceId", "sourceNonClaimRefs", "sourceNonClaims", "specPackagePath", "vocabulary"}
	if !slices.Equal(required, want) || schema["additionalProperties"] != false {
		t.Fatalf("flat root inventory = %v", required)
	}
	properties := schema["properties"].(map[string]any)
	bound := func(name string) any { return properties[name].(map[string]any)["maxItems"] }
	for name, limit := range map[string]int{"requirements": limits.MaxMembers, "groups": limits.MaxGroups, "profiles": limits.MaxProfiles} {
		if fmt.Sprint(bound(name)) != fmt.Sprint(limit) {
			t.Fatalf("%s maxItems = %v, want %d", name, bound(name), limit)
		}
	}
	for _, name := range []string{"nonClaimDefinitions", "vocabulary", "derivations", "scenarios", "sourceNonClaimRefs", "sourceNonClaims"} {
		if !reflect.DeepEqual(properties[name], codec["properties"].(map[string]any)[name]) {
			t.Fatalf("flat %s does not reuse the grouped structure", name)
		}
	}
}
