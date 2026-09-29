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

func TestNestedStructuresOwnJSONValueCarriers(t *testing.T) {
	record := Record{
		Diagnostics: []Diagnostic{{Key: "observation", Value: true}},
		RuleResults: []RuleResult{{RuleID: "rule.example", Status: "passed", Message: "Observed.", Diagnostics: []Diagnostic{{Key: "count", Value: 3}}}},
	}
	diagnostic := DiagnosticStructure("observation", jsonshape.Boolean())
	rule := RuleStructure(jsonshape.StringLiteral("rule.example"), jsonshape.StringLiteral("passed"),
		jsonshape.StringLiteral("Observed."), jsonshape.Tuple(DiagnosticStructure("count", jsonshape.IntegerMinimum(0))))
	for _, test := range []struct {
		name  string
		shape jsonshape.Shape
		keys  []string
	}{
		{"diagnostics", diagnostic, []string{"key", "value"}},
		{"ruleResults", rule, []string{"diagnostics", "message", "ruleId", "status"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := func() map[string]any { return record.JSONValue()[test.name].([]any)[0].(map[string]any) }
			if err := test.shape.CheckGenerated(value(), "record"); err != nil {
				t.Fatal(err)
			}
			want := make([]any, len(test.keys))
			for i, key := range test.keys {
				want[i] = key
			}
			if !reflect.DeepEqual(test.shape.JSONSchema()["required"], want) {
				t.Fatal("nested carrier inventory differs")
			}
			for _, key := range test.keys {
				changed := value()
				delete(changed, key)
				if err := test.shape.CheckGenerated(changed, "record"); err == nil {
					t.Fatalf("missing %s admitted", key)
				}
			}
			changed := value()
			changed["extra"] = true
			if err := test.shape.CheckGenerated(changed, "record"); err == nil {
				t.Fatal("extra carrier field admitted")
			}
		})
	}
}
