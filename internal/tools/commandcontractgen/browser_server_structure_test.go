package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
)

type browserOwnerRow struct {
	id, command, direction, contractID, version, predecessor string
	variants                                                 [][2]string
}

// Independently stated public identities and predecessor variant conditions.
var browserOwnerRows = []browserOwnerRow{
	{"proofkit.requirement-browser-server.input.v4.json-schema", "requirement-browser-server", "input", "proofkit.requirement-browser-server.input.v4", "4",
		"proofkit.requirement-browser-server.input.v4.root-shape", [][2]string{
			{"01-coverage-compact", "--view coverage; compact proof"}, {"02-coverage-structured", "--view coverage; structured proof"},
			{"03-proof-compact", "--view proof; compact proof"}, {"04-proof-structured", "--view proof; structured proof"},
			{"05-source", "--view source"}, {"06-spec-tree", "--view spec-tree"}, {"07-workspace", "--view workspace"},
		}},
	{"proofkit.requirement-browser-server.output.v2.json-schema", "requirement-browser-server", "output", "proofkit.requirement-browser-server.output.v2", "2",
		"proofkit.requirement-browser-server.output.v2.root-shape", [][2]string{
			{"01-plan-coverage", "without --serve; --view coverage"}, {"01-plan-proof", "without --serve; --view proof"},
			{"01-plan-source", "without --serve; --view source"}, {"01-plan-spec-tree", "without --serve; --view spec-tree"},
			{"01-plan-workspace", "without --serve; --view workspace"},
			{"02-one-shot-terminal", "--open; --serve; --session-mode one-shot-question; --view workspace; state=cancelled|expired"},
			{"03-one-shot-submitted", "--open; --serve; --session-mode one-shot-question; --view workspace; state=submitted"},
		}},
	{"proofkit.view.output.v2.json-schema", "view", "output", "proofkit.view.output.v2", "1",
		"proofkit.view.output.v1.root-shape", [][2]string{
			{"01-plan", "without --serve"},
			{"02-one-shot-terminal", "--open; --serve; --session-mode one-shot-question; state=cancelled|expired"},
			{"03-one-shot-submitted", "--open; --serve; --session-mode one-shot-question; state=submitted"},
		}},
}

func TestBrowserStructureOwnersConserveIdentityAndPredecessorConditions(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := admitNativeStructureConsumers(contract, definitions); err != nil {
		t.Fatal(err)
	}
	for _, row := range browserOwnerRows {
		owner, ok := nativeStructureOwner(row.id)
		if !ok || owner.direction != row.direction || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{row.predecessor}) {
			t.Fatalf("wrong browser owner binding: %s", row.id)
		}
		definition, err := owner.definition()
		if err != nil {
			t.Fatal(err)
		}
		if err := admitNativeStructureDefinition(row.id, definition); err != nil {
			t.Fatal(err)
		}
		version, err := owner.contractVersion(definition)
		if err != nil || version != json.Number(row.version) || owner.contractID(row.command, version) != row.contractID {
			t.Fatalf("contract identity drifted for %s: %s %v", row.id, version, err)
		}
		binding := commandAt(contract, row.command)[row.direction+"Contract"].(map[string]any)
		if binding["rootDefinitionRef"] != row.id || binding["contractId"] != row.contractID || binding["schemaVersion"] != json.Number(row.version) {
			t.Fatalf("published %s %s identity was not conserved: %v", row.command, row.direction, binding)
		}
		if _, retained := definitions[row.predecessor]; retained {
			t.Fatalf("predecessor %s remains published", row.predecessor)
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		if len(variants) != len(row.variants) {
			t.Fatalf("%s variant count=%d", row.id, len(variants))
		}
		for index, raw := range variants {
			variant := raw.(map[string]any)
			if variant["variantId"] != row.variants[index][0] || !reflect.DeepEqual(variant["when"], []any{row.variants[index][1]}) || variant["rootKind"] != "object" {
				t.Fatalf("%s variant %d drifted: %v %v", row.id, index, variant["variantId"], variant["when"])
			}
			expected, err := owner.variants[index].schema()
			if err != nil || !equalPublishedSchema(variant["schema"], expected) {
				t.Fatalf("%s variant %s is not owner derived", row.id, variant["variantId"])
			}
		}
		for _, mutation := range []string{"open", "required", "nested"} {
			changed, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			last := changed["fieldTree"].(map[string]any)["variants"].([]any)
			schema := last[len(last)-1].(map[string]any)["schema"].(map[string]any)
			switch mutation {
			case "open":
				schema["additionalProperties"] = true
			case "required":
				schema["required"] = []any{}
			case "nested":
				schema["properties"].(map[string]any)["schemaVersion"] = map[string]any{"type": "string"}
			}
			delete(changed, "canonicalDigest")
			encoded, err := canonicalJSON(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed["canonicalDigest"] = sha256Digest(encoded)
			if admitNativeStructureDefinition(row.id, changed) == nil {
				t.Fatalf("accepted rehashed %s/%s drift", row.id, mutation)
			}
		}
	}
	plan, err := requirementbrowser.PlanOutputStructure("workspace")
	view, _ := nativeStructureOwner("proofkit.view.output.v2.json-schema")
	projectPlan, projectErr := view.variants[0].schema()
	if err != nil || projectErr != nil || !reflect.DeepEqual(plan, projectPlan) {
		t.Fatal("project view plan differs from the explicit workspace browser plan")
	}
}

func TestBrowserInputChildBindingsCheckOnlyCarryingVariants(t *testing.T) {
	_, contract, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		t.Fatal(err)
	}
	input := commandAt(contract, "requirement-browser-server")["inputContract"].(map[string]any)
	root := definitions[input["rootDefinitionRef"].(string)]
	// The unscoped requirementSource binding appears only in the coverage
	// variants; later variants without that member must not inherit the path.
	if err := admitChildBindings("requirement-browser-server", "input", input, root, definitions); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ variant, member string }{{"02-coverage-structured", "requirementSource"}, {"07-workspace", "context"}, {"01-coverage-compact", "compactProofContract"}} {
		changed := cloneRecord(root.Content)
		tree := cloneRecord(changed["fieldTree"].(map[string]any))
		changed["fieldTree"] = tree
		variants := slices.Clone(tree["variants"].([]any))
		tree["variants"] = variants
		for index, raw := range variants {
			variant := cloneRecord(raw.(map[string]any))
			if variant["variantId"] != mutation.variant {
				continue
			}
			schema := cloneRecord(variant["schema"].(map[string]any))
			properties := cloneRecord(schema["properties"].(map[string]any))
			properties[mutation.member] = map[string]any{"type": "object"}
			schema["properties"], variant["schema"] = properties, schema
			variants[index] = variant
		}
		if admitChildBindings("requirement-browser-server", "input", input, definitionRecord{ID: root.ID, Content: changed, Digest: root.Digest}, definitions) == nil {
			t.Fatalf("%s/%s lost its bound source owner", mutation.variant, mutation.member)
		}
	}
}

func TestChildPathCrossesOnlyAgreeingValueUnions(t *testing.T) {
	child := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"id": map[string]any{"type": "string"}}}
	branch := func(leaf map[string]any, extra string) map[string]any {
		properties := map[string]any{"items": map[string]any{"type": "array", "items": leaf}}
		if extra != "" {
			properties[extra] = map[string]any{"type": "string"}
		}
		return map[string]any{"type": "object", "properties": properties}
	}
	other := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"id": map[string]any{"type": "integer"}}}
	path := []any{"value", "items", "*"}
	for label, row := range map[string]struct {
		value map[string]any
		ok    bool
	}{
		"agreeing-oneOf":    {map[string]any{"oneOf": []any{branch(child, "a"), branch(child, "b")}}, true},
		"agreeing-anyOf":    {map[string]any{"anyOf": []any{map[string]any{"type": "null"}, branch(child, ""), branch(child, "c")}}, true},
		"referenced-oneOf":  {map[string]any{"$ref": "#/$defs/sum"}, true},
		"disagreeing-oneOf": {map[string]any{"oneOf": []any{branch(child, ""), branch(other, "")}}, false},
		"missing-branch":    {map[string]any{"oneOf": []any{branch(child, ""), map[string]any{"type": "string"}}}, false},
		"null-only":         {map[string]any{"anyOf": []any{map[string]any{"type": "null"}}}, false},
	} {
		schema := map[string]any{"type": "object", "properties": map[string]any{"value": row.value},
			"$defs": map[string]any{"sum": map[string]any{"oneOf": []any{branch(child, "a"), branch(child, "b")}}}}
		leaf, err := schemaChildAtPath(schema, path)
		if (err == nil && equalBoundChildSchema(leaf, child)) != row.ok {
			t.Fatalf("%s union traversal=%v %v", label, leaf, err)
		}
	}
	// A oneOf beside object members is a constraint partition, not a value sum.
	constrained := map[string]any{"type": "object", "properties": map[string]any{"value": child}, "oneOf": []any{map[string]any{"required": []any{"value"}}}}
	if leaf, err := schemaChildAtPath(constrained, []any{"value"}); err != nil || !equalBoundChildSchema(leaf, child) {
		t.Fatalf("constraint partition hid an object member: %v", err)
	}
}

func TestViewLegacyRootShapeNoteRetiresOnlyWithItsPredecessor(t *testing.T) {
	legacy := "Root-shape-only variants; nested fields, semantic admission, host effects and complete execution remain native-owner and native-witness claims."
	policy := "Graph shows declared relations only; coverage and diff are unavailable."
	view, _ := nativeStructureOwner("proofkit.view.output.v2.json-schema")
	got, err := enrichedCompatibilitySummary(view, "1", []any{"No JSON input.", legacy, policy})
	if err != nil || !reflect.DeepEqual(got, append(view.summary("1"), "No JSON input.", policy)) {
		t.Fatalf("view legacy note was not retired exactly: %v %v", got, err)
	}
	browser, _ := nativeStructureOwner("proofkit.requirement-browser-server.output.v2.json-schema")
	got, err = enrichedCompatibilitySummary(browser, "2", []any{"aggregate output contract v2", legacy})
	if err != nil || !slices.Contains(got, any(legacy)) {
		t.Fatal("a legacy note was retired by an owner that does not own it")
	}
	got, err = enrichedCompatibilitySummary(view, "1", []any{"No JSON input.", legacy + " Extra policy."})
	if err != nil || !slices.Contains(got, any(legacy+" Extra policy.")) {
		t.Fatal("an extended independent note was dropped as obsolete")
	}
}
