package report

import (
	"reflect"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestStructureOwnsJSONValueCarrierWithoutInventingPayloadAuthority(t *testing.T) {
	shape := Structure(2, "proofkit.fixture", jsonshape.StringLiteral("passed"), jsonshape.Object(jsonshape.Required("count", jsonshape.IntegerMinimum(0))), jsonshape.Tuple(), jsonshape.Tuple())
	record := Record{SchemaVersion: 2, ReportKind: "proofkit.fixture", ReportID: "fixture", State: "passed", Summary: map[string]any{"count": 1}, NonClaims: []any{"Fixture only."}}
	value := record.JSONValue()
	if err := shape.CheckGenerated(value, "fixture"); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatal("report carrier changed")
	}
	if !reflect.DeepEqual(shape.JSONSchema()["required"], []any{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}) {
		t.Fatal("structural carrier differs from JSONValue")
	}
	for _, key := range keys {
		mutated := record.JSONValue()
		delete(mutated, key)
		if err := shape.CheckGenerated(mutated, "fixture"); err == nil {
			t.Fatalf("missing %s admitted", key)
		}
	}
	value["summary"] = map[string]any{"arbitrary": true}
	if err := shape.CheckGenerated(value, "fixture"); err == nil {
		t.Fatal("envelope weakened the command-owned summary")
	}
}
