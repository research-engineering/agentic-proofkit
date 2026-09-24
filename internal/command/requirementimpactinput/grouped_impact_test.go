package requirementimpactinput

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

func TestFingerprintDependsOnEveryEffectiveRequirementOperand(t *testing.T) {
	input := validComposeInput(t)
	result, err := requirementsourceadmission.Evaluate(input["currentRequirementSources"].([]any)[0])
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("source fixture: %v, %v", err, result.Failures)
	}
	base := result.Source.Requirements()[0]
	// Fingerprinting is a projection, not admission; a populated pointer lets the
	// independent field walk also exercise every nested deferral operand.
	base.Deferral = &requirementsourceadmission.Deferral{}
	var visit func(reflect.Type, []int, string)
	visit = func(typ reflect.Type, indexes []int, path string) {
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			index := append(append([]int{}, indexes...), i)
			name := path + "/" + field.Name
			child := field.Type
			if child.Kind() == reflect.Pointer {
				child = child.Elem()
			}
			if child.Kind() == reflect.Struct {
				visit(child, index, name)
				continue
			}
			t.Run(name, func(t *testing.T) {
				mutated := base
				if base.Deferral != nil {
					copy := *base.Deferral
					mutated.Deferral = &copy
				}
				value := reflect.ValueOf(&mutated).Elem()
				for _, n := range index {
					if value.Kind() == reflect.Pointer {
						value = value.Elem()
					}
					value = value.Field(n)
				}
				switch value.Kind() {
				case reflect.String:
					value.SetString(value.String() + ".changed")
				case reflect.Bool:
					value.SetBool(!value.Bool())
				case reflect.Slice:
					if value.Type().Elem().Kind() != reflect.String {
						t.Fatalf("unhandled fingerprint field %s", name)
					}
					value.Set(reflect.Append(value, reflect.ValueOf("changed.operand")))
				default:
					t.Fatalf("unhandled fingerprint field %s", name)
				}
				if requirementFingerprint(base) == requirementFingerprint(mutated) {
					t.Fatal("changed effective operand did not change fingerprint")
				}
			})
		}
	}
	visit(reflect.TypeFor[requirementsourceadmission.Requirement](), nil, "")
}

func TestGroupedEffectiveChangesReachDownstreamImpact(t *testing.T) {
	for _, field := range []string{"sharedPremises", "externalNonClaimRefs", "profile", "layout"} {
		t.Run(field, func(t *testing.T) {
			input := validComposeInput(t)
			source := input["currentRequirementSources"].([]any)[0].(map[string]any)
			group := impactSourceGroup(source)
			members := group["members"].([]any)
			want := []string{"REQ-PROOFKIT-IMPACT-001", "REQ-PROOFKIT-IMPACT-002", "REQ-PROOFKIT-IMPACT-003"}
			switch field {
			case "sharedPremises":
				group[field] = []any{"Only authenticated callers enter this operation."}
			case "externalNonClaimRefs":
				members[0].(map[string]any)["fields"].(map[string]any)[field] = []any{"consumer.external-boundary"}
				want = want[:1]
			case "profile":
				group["profileId"] = "RPROF-IMPACT"
				source["profiles"] = []any{map[string]any{"profileId": "RPROF-IMPACT", "fields": map[string]any{"riskClass": "high"}}}
				for _, member := range members {
					delete(member.(map[string]any)["fields"].(map[string]any), "riskClass")
				}
			case "layout":
				group["groupId"] = "RGRP-RENAMED"
				want = []string{}
			}
			output, exit, err := Build(input)
			if err != nil || exit != 0 {
				t.Fatalf("Build(): %v, exit %d", err, exit)
			}
			admitted, err := admitInput(input)
			if err != nil {
				t.Fatal(err)
			}
			allChanged, failures := changedRequirementIDs(admitted.BaseRequirements, admitted.CurrentRequirements)
			if len(failures) != 0 || !reflect.DeepEqual(allChanged, want) {
				t.Fatalf("effective changes = %v, failures %v; want %v", allChanged, failures, want)
			}
			// Public changedRequirementIds is deliberately the active blocking
			// routed subset, not the complete semantic delta.
			if len(want) == 3 {
				want = want[:2]
			}
			assertStringArray(t, output["changedRequirementIds"], want)
			report, exit, err := impact.Build(output)
			if err != nil || exit != 0 {
				t.Fatalf("impact: %v, exit %d", err, exit)
			}
			wantObligations := len(want)
			if len(report["obligations"].([]any)) != wantObligations {
				t.Fatalf("obligations do not match changed blocking requirements: %#v", report)
			}
		})
	}
}

func TestGroupedImpactRejectsOldInputIdentity(t *testing.T) {
	input := validComposeInput(t)
	input["schemaVersion"] = json.Number("2")
	out, code, err := Build(input)
	if err == nil || code != 1 || out != nil || !strings.Contains(err.Error(), "schemaVersion must be 3") {
		t.Fatalf("old identity accepted: %v, %d, %v", out, code, err)
	}
}
