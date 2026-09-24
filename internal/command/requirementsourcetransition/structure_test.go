package requirementsourcetransition

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func transitionWire(t *testing.T, value any) map[string]any {
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

func TestTransitionStructuresPreserveOutcomeAlgebra(t *testing.T) {
	for _, tc := range []struct {
		name           string
		change         func(map[string]any)
		state, lattice string
		null           bool
	}{
		{"same", func(map[string]any) {}, "passed", "passed", false},
		{"source failure", func(v map[string]any) { firstRequirement(v["next"].(map[string]any))["proofBindingRefs"] = []any{} }, "failed", "skipped", true},
		{"boundary failure", func(v map[string]any) { v["next"].(map[string]any)["sourceId"] = "different.source" }, "failed", "skipped", false},
		{"lattice failure", func(v map[string]any) { v["next"].(map[string]any)["groups"] = []any{} }, "failed", "failed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := validRequirementSourceTransitionInput(false)
			tc.change(input)
			if _, err := transitionInputShape.Admit(input, "input"); err != nil {
				t.Fatal(err)
			}
			record, exit, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			if record.State != tc.state || (exit != 0) != (tc.state == "failed") || record.RuleResults[2].Status != tc.lattice {
				t.Fatal("output structure changed the outcome algebra")
			}
			for _, key := range []string{"addedRequirementCount", "missingRequirementCount", "lifecycleChangedRequirementCount"} {
				if (record.Summary[key] == nil) != tc.null {
					t.Fatal("comparison presence changed")
				}
			}
			wire := transitionWire(t, record.JSONValue())
			admitted, err := transitionOutputShape.Admit(wire, "output")
			if err != nil || !reflect.DeepEqual(admitted, wire) {
				t.Fatalf("wire report differs: %v", err)
			}
		})
	}
	source, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	delete(source, "$schema")
	properties := InputStructure()["properties"].(map[string]any)
	for _, key := range []string{"previous", "next"} {
		if !reflect.DeepEqual(properties[key], source) {
			t.Fatal("nested source structural policy drift")
		}
	}
}

func TestTransitionStructureRejectsIndependentInputAndOutputCorruptions(t *testing.T) {
	input := validRequirementSourceTransitionInput(false)
	owned, err := admitInput(input)
	if err != nil {
		t.Fatal(err)
	}
	firstRequirement(input["next"].(map[string]any))["ownerId"] = "changed.owner"
	if firstRequirement(owned.Next)["ownerId"] == "changed.owner" {
		t.Fatal("admitted transition retained a caller alias")
	}
	for _, key := range []string{"schemaVersion", "transitionId", "nonClaims", "previous", "next"} {
		for _, replacement := range []any{nil, true} {
			v := validRequirementSourceTransitionInput(false)
			v[key] = replacement
			if _, _, err := Build(v); err == nil {
				t.Fatalf("malformed %s admitted", key)
			}
		}
		v := validRequirementSourceTransitionInput(false)
		delete(v, key)
		if _, _, err := Build(v); err == nil {
			t.Fatalf("missing %s admitted", key)
		}
	}
	v := validRequirementSourceTransitionInput(false)
	v["schemaVersion"] = json.Number("2.0")
	if _, _, err := Build(v); err == nil {
		t.Fatal("noncanonical version admitted")
	}
	for _, where := range []string{"previous", "next"} {
		v := validRequirementSourceTransitionInput(false)
		v[where].(map[string]any)["unknown"] = true
		if _, _, err := Build(v); err == nil {
			t.Fatal("unknown nested source field admitted")
		}
	}
	record, _, err := Build(validRequirementSourceTransitionInput(false))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"unknown":                func(v map[string]any) { v["other"] = true },
		"nonnullable count":      func(v map[string]any) { v["summary"].(map[string]any)["previousRequirementCount"] = nil },
		"wrong nullable count":   func(v map[string]any) { v["summary"].(map[string]any)["addedRequirementCount"] = "0" },
		"wrong state":            func(v map[string]any) { v["state"] = "approved" },
		"wrong diagnostic order": func(v map[string]any) { rows := v["diagnostics"].([]any); rows[0], rows[1] = rows[1], rows[0] },
		"short paths":            func(v map[string]any) { v["diagnostics"].([]any)[1].(map[string]any)["value"] = []any{} },
		"invented lattice state": func(v map[string]any) { v["ruleResults"].([]any)[2].(map[string]any)["status"] = "blocked" },
		"missing rule":           func(v map[string]any) { v["ruleResults"] = v["ruleResults"].([]any)[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			wire := transitionWire(t, record.JSONValue())
			change(wire)
			if err := transitionOutputShape.CheckGenerated(wire, "output"); err == nil {
				t.Fatal("invalid report structure admitted")
			}
		})
	}
}
