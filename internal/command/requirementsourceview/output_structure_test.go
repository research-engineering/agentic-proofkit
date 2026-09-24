package requirementsourceview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func sourceViewWire(t *testing.T, value any) map[string]any {
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

func TestSourceViewOutputStructureCoversCompleteNativeViews(t *testing.T) {
	for _, input := range []map[string]any{validRequirementSource(), declaredSourceFixture()} {
		value, exit, err := BuildJSON(input)
		if err != nil || exit != 0 {
			t.Fatal(err)
		}
		wire := sourceViewWire(t, value)
		admitted, err := sourceViewShape.Admit(wire, "view")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(admitted, wire) {
			t.Fatal("output admission changed the emitted view")
		}
	}
	source, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	properties := OutputStructure()["properties"].(map[string]any)
	for _, key := range []string{"nonClaimDefinitions", "sourceNonClaimRefs", "vocabulary", "scenarios", "derivations"} {
		if !reflect.DeepEqual(properties[key], source["properties"].(map[string]any)[key]) {
			t.Fatalf("duplicated source policy for %s", key)
		}
	}
}

func TestSourceViewOutputStructureRejectsNestedCorruption(t *testing.T) {
	base, exit, err := BuildJSON(declaredSourceFixture())
	if err != nil || exit != 0 {
		t.Fatal(err)
	}
	row := func(v map[string]any) map[string]any { return v["requirements"].([]any)[0].(map[string]any) }
	mutations := map[string]func(map[string]any){
		"unknown root":           func(v map[string]any) { v["unknown"] = true },
		"wrong version":          func(v map[string]any) { v["schemaVersion"] = json.Number("1") },
		"wrong authority":        func(v map[string]any) { v["authority"] = "proof" },
		"unknown row":            func(v map[string]any) { row(v)["unknown"] = true },
		"missing canonical flag": func(v map[string]any) { delete(row(v)["updatePolicy"].(map[string]any), "requiresImpactDeclaration") },
		"boolean carrier":        func(v map[string]any) { row(v)["updatePolicy"].(map[string]any)["requiresProofBindingReview"] = "true" },
		"nullable deferral":      func(v map[string]any) { row(v)["deferral"] = map[string]any{} },
		"nested null":            func(v map[string]any) { v["scenarios"] = nil },
		"unknown scenario":       func(v map[string]any) { v["scenarios"].([]any)[0].(map[string]any)["unknown"] = true },
		"wrong example": func(v map[string]any) {
			v["scenarios"].([]any)[0].(map[string]any)["examples"].([]any)[0].(map[string]any)["values"].(map[string]any)["surface"] = false
		},
		"bad decimal coordinate": func(v map[string]any) {
			v["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)["start"] = "-0"
		},
		"vocabulary type":   func(v map[string]any) { v["vocabulary"].([]any)[0].(map[string]any)["definition"] = true },
		"empty group index": func(v map[string]any) { v["groups"].([]any)[0].(map[string]any)["requirementIds"] = []any{} },
	}
	for key := range base.(map[string]any) {
		mutations["missing "+key] = func(v map[string]any) { delete(v, key) }
	}
	for key := range row(base.(map[string]any)) {
		mutations["missing row "+key] = func(v map[string]any) { delete(row(v), key) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := sourceViewWire(t, base)
			mutate(v)
			if err := sourceViewShape.CheckGenerated(v, "view"); err == nil {
				t.Fatal("nested output corruption accepted")
			}
		})
	}
}

func TestSourceViewOutputStructureGroupCardinalityBoundary(t *testing.T) {
	base, exit, err := BuildJSON(declaredSourceFixture())
	if err != nil || exit != 0 {
		t.Fatal(err)
	}
	limit := requirementsourcemodel.DefaultLimits().MaxGroups
	for _, count := range []int{limit, limit + 1} {
		wire := sourceViewWire(t, base)
		groups := make([]any, count)
		for index := range groups {
			groups[index] = map[string]any{
				"groupId": fmt.Sprintf("RGRP-BOUND-%d", index), "statementStem": "", "sharedPremises": []any{},
				"requirementIds": []any{fmt.Sprintf("REQ-BOUND-%d", index)},
			}
		}
		wire["groups"] = groups
		err := sourceViewShape.CheckGenerated(wire, "view")
		if count == limit && err != nil {
			t.Fatalf("exact structural group bound rejected: %v", err)
		}
		if count > limit && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf(".groups must contain at most %d items", limit))) {
			t.Fatalf("group cardinality guard did not reject valid-shaped excess: %v", err)
		}
	}
}
