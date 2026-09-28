package requirementdiff

import (
	"encoding/json"
	"testing"
)

func diffStructureInput(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{"schemaVersion": json.Number("3"), "diffId": "diff.structure", "baseContext": contextFixture(t, "Before."), "currentContext": contextFixture(t, "After.")}
}

func TestDiffNumericStructureMatchesWholeOperation(t *testing.T) {
	for _, test := range []struct {
		token string
		valid bool
	}{
		{"1", true}, {"8192", true}, {"0", false}, {"-0", false}, {"-1", false},
		{"8193", false}, {"1.0", false}, {"1e0", false}, {"9223372036854775808", false},
	} {
		t.Run(test.token, func(t *testing.T) {
			input := diffStructureInput(t)
			input["query"] = map[string]any{"maxChanges": json.Number(test.token)}
			_, nativeErr := Build(input)
			_, shapeErr := diffInputShape.Admit(input, "diff")
			if (nativeErr == nil) != test.valid || (shapeErr == nil) != test.valid {
				t.Fatalf("expected admission %v, native=%v shape=%v", test.valid, nativeErr, shapeErr)
			}
		})
	}
	for _, raw := range []any{nil, map[string]any{}, map[string]any{"maxChanges": nil}} {
		query, err := admitQuery(raw)
		if err != nil || query.MaxChanges != 8192 {
			t.Fatalf("native default drifted: %+v, %v", query, err)
		}
	}
	querySchema := InputStructure()["properties"].(map[string]any)["query"].(map[string]any)["anyOf"].([]any)[1].(map[string]any)
	limit := querySchema["properties"].(map[string]any)["maxChanges"].(map[string]any)
	integer := limit["anyOf"].([]any)[1].(map[string]any)
	if integer["type"] != "integer" || integer["minimum"] != json.Number("1") || integer["maximum"] != json.Number("8192") || limit["default"] != json.Number("8192") {
		t.Fatal("numeric schema does not describe the native limits and default")
	}
}

func TestDiffNativeLimitDiagnosticsAndPrecedence(t *testing.T) {
	for _, query := range []map[string]any{
		{"maxChanges": json.Number("8193")},
		{"maxChanges": json.Number("8193"), "ownerIds": true},
	} {
		input := diffStructureInput(t)
		input["query"] = query
		_, directErr := admitQuery(query)
		_, operationErr := Build(input)
		for _, err := range []error{directErr, operationErr} {
			const want = "requirement semantic diff maxChanges must be between 1 and 8192"
			if err == nil || err.Error() != want {
				t.Fatalf("numeric diagnostic = %v, want %q", err, want)
			}
		}
	}
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
