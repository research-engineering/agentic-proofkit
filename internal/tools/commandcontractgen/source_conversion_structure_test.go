package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceconversion"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/schemadefs"
)

// Each closed --to target has exactly one published variant per direction.
// The contract identity is the conversion's own aggregate version 1, while
// each variant keeps its artifact's wire version: grouped 2 and flat 1.
func TestSourceConversionVariantsCoverTheClosedTargetVocabulary(t *testing.T) {
	grouped, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		direction string
		targets   map[string]json.Number
		grouped   string
	}{
		{"input", map[string]json.Number{"flat": "2", "grouped": "1"}, "flat"},
		{"output", map[string]json.Number{"flat": "1", "grouped": "2"}, "grouped"},
	} {
		id := "proofkit.requirement-source-conversion." + item.direction + ".v1.json-schema"
		owner, exists := nativeStructureOwner(id)
		if !exists {
			t.Fatalf("missing owner %s", id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		if err := admitNativeStructureDefinition(id, definition); err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number("1") || owner.contractID("requirement-source-conversion", version) != "proofkit.requirement-source-conversion."+item.direction+".v1" {
			t.Fatalf("%s contract identity = %s, %v", item.direction, version, err)
		}
		selected := []string{}
		for _, raw := range definition["fieldTree"].(map[string]any)["variants"].([]any) {
			variant := raw.(map[string]any)
			when := variant["when"].([]any)
			condition, ok := when[0].(string)
			if len(when) != 1 || !ok || !strings.HasPrefix(condition, "--to ") {
				t.Fatalf("%s variant condition %v is not one --to selection", item.direction, when)
			}
			target := strings.Fields(condition)[1]
			selected = append(selected, target)
			// The published schema shares repeated subtrees; version navigation
			// and owner equality read its expansion, the native owner schema.
			published := variant["schema"].(map[string]any)
			schema, err := schemadefs.Expand(published)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := nativeSchemaVersion(schema, "schemaVersion")
			if err != nil || wire != item.targets[target] {
				t.Fatalf("%s --to %s wire version = %s, %v", item.direction, target, wire, err)
			}
			if target == item.grouped && !equalPublishedSchema(published, grouped) {
				t.Fatalf("%s --to %s does not publish the grouped codec structure", item.direction, target)
			}
		}
		slices.Sort(selected)
		if !slices.Equal(selected, requirementsourceconversion.TargetChoices()) {
			t.Fatalf("%s variants select %v, want %v", item.direction, selected, requirementsourceconversion.TargetChoices())
		}
	}
}
