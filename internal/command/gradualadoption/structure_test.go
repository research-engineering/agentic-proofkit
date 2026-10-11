package gradualadoption

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestReportStructuresPreserveFailureNormalizedCarriers(t *testing.T) {
	for _, field := range []string{"agentReport", "budget", "module", "proofBinding", "repository", "rollback"} {
		t.Run(field, func(t *testing.T) {
			input := validAdoptionInput()
			input[field] = map[string]any{}
			value, code, err := Build(input)
			if err != nil || code != 1 || value["state"] != "failed" {
				t.Fatalf("evaluation failure changed phase: code=%d err=%v", code, err)
			}
			if err := adoptionReportShape().CheckGenerated(value, "adoption report"); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, mode := range []string{"observe", "warn", "enforce-touched", "enforce-all"} {
		for _, state := range []string{"passed", "failed", "blocked", "warning", "skipped"} {
			t.Run(mode+"/"+state, func(t *testing.T) {
				input := validGuidanceInput()
				input["guidanceMode"] = mode
				input["sourceReport"].(map[string]any)["state"] = state
				value, _, err := BuildGuidance(input, GuidanceOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if err := guidanceReportShape().CheckGenerated(value, "guidance report"); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestGuidanceSourceStructureRetainsIgnoredJSONAndOptionalModernization(t *testing.T) {
	schema := GuidanceInputStructure()
	required := schema["required"].([]any)
	want := []any{"guidanceId", "guidanceMode", "nonClaims", "schemaVersion", "sourceReport"}
	if !reflect.DeepEqual(required, want) {
		t.Fatalf("hard input members changed: %v", required)
	}
	fields := schema["properties"].(map[string]any)
	for _, key := range []string{"scopeEvidence", "agentGuidance", "ownerRoute", "modernization"} {
		if _, constrained := fields[key].(map[string]any)["type"]; constrained {
			t.Fatalf("%s narrowed a failure-collecting JSON domain", key)
		}
	}
	for _, raw := range []any{nil, false, json.Number("0"), "", []any{}, map[string]any{"nested": []any{true, nil}}} {
		input := validGuidanceInput()
		source := input["sourceReport"].(map[string]any)
		for _, key := range []string{"diagnostics", "nonClaims", "summary"} {
			source[key] = raw
		}
		source["ruleResults"] = []any{map[string]any{"ruleId": "proofkit.test.rule", "status": "passed", "diagnostics": raw, "message": raw}}
		value, code, err := BuildGuidance(input, GuidanceOptions{})
		if err != nil || code != 0 || value["state"] != "passed" {
			t.Fatalf("ignored source payload became input authority: %v %d", err, code)
		}
	}
}

func TestBootstrapStructureRemainsDetachedOnProjection(t *testing.T) {
	first := BootstrapInputStructure()
	first["properties"].(map[string]any)["bootstrapId"] = map[string]any{"const": "foreign"}
	second := BootstrapInputStructure()
	if reflect.DeepEqual(first, second) {
		t.Fatal("structure projection aliases a prior caller")
	}
	for _, field := range []string{"module", "ownerRoute", "paths", "checkedScope", "commands", "nonClaims", "proofBindingPath", "touchedRuleIds"} {
		if _, narrowed := second["properties"].(map[string]any)[field].(map[string]any)["type"]; narrowed {
			t.Fatalf("bootstrap %s acquired a hard successful-output shape", field)
		}
	}
}
