package requirementsourceadmission

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestSourceOutputStructureAcceptsActualPassedAndFailedWireReports(t *testing.T) {
	for _, failed := range []bool{false, true} {
		input := validSource()
		if failed {
			sourceMember(input, 0)["fields"].(map[string]any)["proofBindingRefs"] = []any{}
		}
		result, err := Evaluate(input)
		if err != nil {
			t.Fatal(err)
		}
		if (result.Report.State == "failed") != failed {
			t.Fatal("structural checks changed the semantic outcome")
		}
		wire := outputWire(t, result.Report.JSONValue())
		if _, err := sourceOutputShape.Admit(wire, "output"); err != nil {
			t.Fatal(err)
		}
		if err := sourceOutputShape.CheckGenerated(result.Report.JSONValue(), "output"); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(wire["diagnostics"].([]any)[0].(map[string]any)["key"], "failures") || len(wire["ruleResults"].([]any)) != 3 {
			t.Fatal("report-owned layout changed")
		}
	}
}

func outputWire(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return wire.(map[string]any)
}

func TestSourceOutputStructureRejectsIsolatedShapeMutations(t *testing.T) {
	input := validSource()
	sourceMember(input, 0)["fields"].(map[string]any)["proofBindingRefs"] = []any{}
	result, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	base := result.Report.JSONValue()
	mutations := map[string]func(map[string]any){
		"unknown root":            func(v map[string]any) { v["other"] = true },
		"wrong version":           func(v map[string]any) { v["schemaVersion"] = "2" },
		"wrong kind":              func(v map[string]any) { v["reportKind"] = "other" },
		"wrong state":             func(v map[string]any) { v["state"] = "unknown" },
		"wrong nonclaims":         func(v map[string]any) { v["nonClaims"] = []any{true} },
		"wrong diagnostic order":  func(v map[string]any) { a := v["diagnostics"].([]any); a[0], a[1] = a[1], a[0] },
		"outer scalar diagnostic": func(v map[string]any) { v["diagnostics"].([]any)[0].(map[string]any)["value"] = "not an array" },
		"extra diagnostic":        func(v map[string]any) { v["diagnostics"] = append(v["diagnostics"].([]any), map[string]any{}) },
		"missing rule":            func(v map[string]any) { v["ruleResults"] = v["ruleResults"].([]any)[:2] },
		"wrong rule identity":     func(v map[string]any) { v["ruleResults"].([]any)[1].(map[string]any)["ruleId"] = boundaryRuleID },
		"unknown rule field":      func(v map[string]any) { v["ruleResults"].([]any)[1].(map[string]any)["other"] = "x" },
		"invented message":        func(v map[string]any) { v["ruleResults"].([]any)[1].(map[string]any)["message"] = "Invented result." },
		"rule diagnostic array": func(v map[string]any) {
			v["ruleResults"].([]any)[1].(map[string]any)["diagnostics"].([]any)[0].(map[string]any)["value"] = []any{"not scalar"}
		},
		"boundary diagnostic": func(v map[string]any) {
			v["ruleResults"].([]any)[0].(map[string]any)["diagnostics"] = []any{map[string]any{"key": "x", "value": "y"}}
		},
	}
	for key := range base {
		mutations["missing "+key] = func(v map[string]any) { delete(v, key) }
	}
	for key := range base["summary"].(map[string]any) {
		mutations["negative "+key] = func(v map[string]any) { v["summary"].(map[string]any)[key] = -1 }
		mutations["missing summary "+key] = func(v map[string]any) { delete(v["summary"].(map[string]any), key) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := outputWire(t, base)
			mutate(v)
			if err := sourceOutputShape.CheckGenerated(v, "output"); err == nil {
				t.Fatal("isolated shape corruption accepted")
			}
		})
	}
}
