package requirementdiff

import (
	"encoding/json"
	"testing"
)

func diffStructureInput(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{"schemaVersion": json.Number("3"), "diffId": "diff.structure", "baseContext": contextFixture(t, "Before."), "currentContext": contextFixture(t, "After.")}
}

func TestDiffInputStructurePreservesQueryDomainAndWholeOperation(t *testing.T) {
	for _, query := range []any{nil, map[string]any{}, map[string]any{"maxChanges": nil, "ownerIds": nil, "requirementIds": nil}, map[string]any{"maxChanges": json.Number("1")}} {
		input := diffStructureInput(t)
		input["query"] = query
		snapshot, err := diffInputShape.Admit(input, "diff")
		if err != nil {
			t.Fatal(err)
		}
		output, err := Build(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if output["changeCount"] != 1 || output["changes"].([]any)[0].(map[string]any)["after"] != "After." {
			t.Fatal("structural input changed diff semantics")
		}
		if _, err := AdmitOutput(output, input["currentContext"].(map[string]any)["snapshotId"].(string)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiffInputStructureRejectsRootQueryAndChildDrift(t *testing.T) {
	for _, mutation := range []string{"old-version", "missing-current", "null-base", "unknown-query", "boolean-limit", "bad-owner-item", "old-source"} {
		t.Run(mutation, func(t *testing.T) {
			input := diffStructureInput(t)
			switch mutation {
			case "old-version":
				input["schemaVersion"] = json.Number("2")
			case "missing-current":
				delete(input, "currentContext")
			case "null-base":
				input["baseContext"] = nil
			case "unknown-query":
				input["query"] = map[string]any{"unknown": true}
			case "boolean-limit":
				input["query"] = map[string]any{"maxChanges": true}
			case "bad-owner-item":
				input["query"] = map[string]any{"ownerIds": []any{false}}
			case "old-source":
				input["currentContext"].(map[string]any)["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["schemaVersion"] = json.Number("1")
			}
			if _, err := diffInputShape.Admit(input, "diff"); err == nil {
				t.Fatal("invalid structure admitted")
			}
			if _, err := Build(input); err == nil {
				t.Fatal("native owner admitted invalid structure")
			}
		})
	}
}
