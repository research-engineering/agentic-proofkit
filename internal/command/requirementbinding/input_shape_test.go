package requirementbinding

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestInputStructureOwnsNestedKeysAndPresence(t *testing.T) {
	input := validRequirementBindingInput()
	input["bindings"].([]any)[0].(map[string]any)["witnessSelectors"] = []any{map[string]any{"command": "go test -run TestBoundary", "selector": "TestBoundary"}}
	for _, object := range []struct {
		name string
		path []any
		keys []string
	}{
		{"root", nil, []string{"schemaVersion", "bindingId", "requirements", "bindings", "witnessCommands", "nonClaims"}},
		{"requirement", []any{"requirements", 0}, []string{"claimLevel", "nonClaims", "ownerId", "proofState", "requirementId", "specPath"}},
		{"binding", []any{"bindings", 0}, []string{"commandIds", "environmentClasses", "requirementId", "scenarioId", "witnessId", "witnessKind", "witnessPath"}},
		{"command", []any{"witnessCommands", 0}, []string{"command", "commandId", "environmentClass"}},
		{"selector", []any{"bindings", 0, "witnessSelectors", 0}, []string{"command", "selector"}},
		{"selection", []any{"selection"}, nil},
	} {
		t.Run(object.name, func(t *testing.T) {
			for _, field := range object.keys {
				for _, mode := range []string{"missing", "null", "wrong-type"} {
					t.Run(field+"/"+mode, func(t *testing.T) {
						raw := cloneBindingShapeInput(t, input)
						record := bindingShapeObject(raw, object.path)
						switch mode {
						case "missing":
							delete(record, field)
						case "null":
							record[field] = nil
						case "wrong-type":
							record[field] = true
						}
						if _, err := bindingInputShape.Admit(raw, "input"); err == nil {
							t.Fatal("structural owner accepted invalid required field")
						}
						if _, err := Build(raw); err == nil {
							t.Fatal("native owner accepted invalid required field")
						}
					})
				}
			}
			raw := cloneBindingShapeInput(t, input)
			bindingShapeObject(raw, object.path)["unexpected"] = true
			if _, err := bindingInputShape.Admit(raw, "input"); err == nil {
				t.Fatal("structural owner accepted unknown nested key")
			}
			if _, err := Build(raw); err == nil {
				t.Fatal("native owner accepted unknown nested key")
			}
		})
	}
}

func TestStructuralAdmissionDoesNotPromoteSemanticFailures(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(raw map[string]any) { raw["bindings"].([]any)[0].(map[string]any)["commandIds"] = []any{} },
		func(raw map[string]any) { raw["bindings"].([]any)[0].(map[string]any)["requirementId"] = "REQ-MISSING" },
		func(raw map[string]any) {
			raw["requirements"] = append(raw["requirements"].([]any), raw["requirements"].([]any)[0])
		},
	} {
		raw := validRequirementBindingInput()
		change(raw)
		if _, err := bindingInputShape.Admit(raw, "binding input"); err != nil {
			t.Fatal("semantic failure was rejected as structural error", err)
		}
		result, err := Build(raw)
		if err != nil || result.Record.State != "failed" {
			t.Fatalf("semantic failure category changed: %v", err)
		}
	}
}

func TestInputStructurePreservesCanonicalOwnerAndOutput(t *testing.T) {
	input := validRequirementBindingInput()
	want, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	input["requirements"].([]any)[0].(map[string]any)["specPath"] = " docs/specs/proofkit-test/requirements.v1.json "
	input["selection"] = map[string]any{"ownerIds": nil}
	before, _ := stablejson.Marshal(input)
	got, err := Build(input)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("native normalization changed: %v", err)
	}
	after, _ := stablejson.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("input mutation")
	}
	for _, claim := range []string{"advisory", "blocking", "deferred"} {
		raw := validRequirementBindingInput()
		raw["requirements"].([]any)[0].(map[string]any)["claimLevel"] = claim
		if _, err := Build(raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		path  []any
		field string
		value any
	}{
		{nil, "schemaVersion", json.Number("1e0")},
		{[]any{"requirements", 0}, "claimLevel", "unknown"},
		{[]any{"requirements", 0}, "proofState", "unknown"},
		{[]any{"bindings", 0}, "witnessKind", "unknown"},
		{[]any{"bindings", 0}, "witnessSelectors", []any{}},
		{[]any{"witnessCommands", 0}, "environmentClasses", nil},
	} {
		raw := validRequirementBindingInput()
		bindingShapeObject(raw, tc.path)[tc.field] = tc.value
		if _, err := bindingInputShape.Admit(raw, "input"); err == nil {
			t.Fatal("structural literal, enum, minimum or variant guard lost")
		}
		if _, err := Build(raw); err == nil {
			t.Fatal("literal, enum, minimum or variant guard lost")
		}
	}
}

func cloneBindingShapeInput(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func bindingShapeObject(root map[string]any, path []any) map[string]any {
	var value any = root
	for _, segment := range path {
		switch segment := segment.(type) {
		case string:
			value = value.(map[string]any)[segment]
		case int:
			value = value.([]any)[segment]
		}
	}
	return value.(map[string]any)
}
