package specproofbundleadmission

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestBundleOutputsSelectExactlyTheirStateBranch(t *testing.T) {
	cases := []struct {
		name     string
		passed   bool
		attached [2]bool
		input    func(*testing.T) map[string]any
	}{
		{"receipt-child", true, [2]bool{true, false}, validBundleInput},
		{"merge-children", true, [2]bool{true, true}, validMergeBundleInput},
		{"no-children", true, [2]bool{false, false}, func(t *testing.T) map[string]any {
			input := validBundleInput(t)
			delete(input, "receiptAdmission")
			delete(input, "receiptProducerAdmission")
			return input
		}},
		{"unknown-selector", false, [2]bool{true, false}, func(t *testing.T) map[string]any {
			input := validBundleInput(t)
			receipt := validProofReceipt()
			receipt["witnessSelectors"] = []any{"REQ-PROOFKIT-UNKNOWN"}
			input["receiptAdmission"].(map[string]any)["receipts"] = []any{receipt}
			return input
		}},
		{"failed-child", false, [2]bool{true, false}, func(t *testing.T) map[string]any {
			input := validBundleInput(t)
			receipt := validProofReceipt()
			receipt["finishedAt"] = "2026-06-21T00:00:00Z"
			child := proofReceiptChild(t, []any{receipt})
			if child["report"].(map[string]any)["state"] != "failed" {
				t.Fatal("fixture did not produce a failed child report")
			}
			child["failures"] = []any{"recorded failure", nil, map[string]any{"opaque": true}}
			input["receiptAdmission"] = child
			return input
		}},
		{"unattached-merge-requirement", false, [2]bool{false, false}, func(t *testing.T) map[string]any {
			input := validBundleInput(t)
			input["receiptAdmission"], input["mergeRequiredReceiptIds"] = nil, []any{"receipt.test.one"}
			return input
		}},
		{"builtin-claim-copy", true, [2]bool{true, false}, func(t *testing.T) map[string]any {
			input := validBundleInput(t)
			input["nonClaims"] = []any{boundaryNonClaims[0], " " + boundaryNonClaims[0]}
			return input
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := bundleWireValue(t, test.input(t))
			record, code, err := Build(input)
			if err != nil || (code == 0) != test.passed {
				t.Fatalf("native phase changed: code=%d err=%v", code, err)
			}
			value := bundleWireValue(t, record.JSONValue())
			if err := OutputShape().CheckGenerated(value, "report"); err != nil {
				t.Fatal(err)
			}
			for _, passed := range []bool{true, false} {
				if (reportShape(passed).CheckGenerated(value, "branch") == nil) != (passed == test.passed) {
					t.Fatalf("branch passed=%t selection drifted", passed)
				}
			}
			children := value["diagnostics"].([]any)[0].(map[string]any)["value"].(map[string]any)
			for index, key := range []string{"receiptAdmissionState", "receiptProducerAdmissionState"} {
				if (children[key] != childState(nil)) != test.attached[index] {
					t.Fatalf("%s attachment drifted: %v", key, children[key])
				}
			}
			if value["summary"].(map[string]any)["receiptProducerAttached"] != test.attached[1] {
				t.Fatal("producer attachment summary drifted")
			}
			if err := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).CheckGenerated(value["reportId"], "reportId"); err != nil {
				t.Fatal(err)
			}
			claims := value["nonClaims"].([]any)
			for _, claim := range boundaryNonClaims {
				if !slices.Contains(claims, any(claim)) {
					t.Fatalf("builtin claim missing: %s", claim)
				}
			}
		})
	}
}

func TestBundleOutputRejectsPassedStateDrift(t *testing.T) {
	record, _, err := Build(bundleWireValue(t, validBundleInput(t)))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"failed-child-state": func(value map[string]any) { bundleChildren(value)["receiptAdmissionState"] = "failed" },
		"failed-owner-state": func(value map[string]any) { bundleChildren(value)["witnessSchedulerState"] = "failed" },
		"unknown-state":      func(value map[string]any) { bundleChildren(value)["requirementBindingState"] = "blocked" },
		"failure-count":      func(value map[string]any) { value["summary"].(map[string]any)["failureCount"] = json.Number("1") },
		"zero-commands": func(value map[string]any) {
			value["summary"].(map[string]any)["witnessCommandCount"] = json.Number("0")
		},
		"rule-id": func(value map[string]any) {
			value["ruleResults"].([]any)[0].(map[string]any)["ruleId"] = failureRuleIDPrefix + "001"
		},
		"extra-child-state": func(value map[string]any) { bundleChildren(value)["foreign"] = "passed" },
	} {
		t.Run(name, func(t *testing.T) {
			value := bundleWireValue(t, record.JSONValue())
			mutate(value)
			if OutputShape().CheckGenerated(value, "report") == nil {
				t.Fatal("drifted report admitted")
			}
		})
	}
}

func TestBundleInputReusesPublishedChildOwners(t *testing.T) {
	schema := InputStructure()
	properties := schema["properties"].(map[string]any)
	if !reflect.DeepEqual(properties["requirementBindings"], requirementbinding.InputStructure()) ||
		!reflect.DeepEqual(properties["witnessPlan"], witnessschedulerplan.InputStructure()) {
		t.Fatal("complete child inputs are not owned by their commands")
	}
	for _, producer := range []bool{false, true} {
		key, owner, report := "receiptAdmission", proofreceiptadmission.InputStructure(), proofreceiptadmission.OutputStructure()
		if producer {
			key, owner, report = "receiptProducerAdmission", receiptproduceradmission.InputStructure(), receiptproduceradmission.OutputStructure()
		}
		wrapper := properties[key].(map[string]any)["anyOf"].([]any)
		if len(wrapper) != 2 || !reflect.DeepEqual(wrapper[0], map[string]any{"type": "null"}) {
			t.Fatalf("%s is not an exact nullable child wrapper", key)
		}
		child := wrapper[1].(map[string]any)
		fields, operands := child["properties"].(map[string]any), owner["properties"].(map[string]any)
		if !reflect.DeepEqual(fields["report"], report) || !reflect.DeepEqual(fields["receipts"], operands["receipts"]) || !reflect.DeepEqual(fields["nonClaims"], operands["nonClaims"]) {
			t.Fatalf("%s operands are not owner structures", key)
		}
		want := slices.Clone(childKeys)
		if producer {
			want = append(want, producerChildKeys...)
			for _, field := range append([]string{"producers"}, producerChildKeys...) {
				if !reflect.DeepEqual(fields[field], operands[field]) {
					t.Fatalf("%s %s is not owner structure", key, field)
				}
			}
		}
		slices.Sort(want)
		if !reflect.DeepEqual(child["required"], admit.StringSliceToAny(want)) || child["additionalProperties"] != false {
			t.Fatalf("%s child inventory drifted", key)
		}
	}
	if !reflect.DeepEqual(schema["required"], []any{"bundleId", "mergeRequiredReceiptIds", "nonClaims", "requirementBindings", "schemaVersion", "witnessPlan"}) {
		t.Fatalf("root required members drifted: %v", schema["required"])
	}
	first := InputStructure()
	first["properties"].(map[string]any)["requirementBindings"].(map[string]any)["required"] = []any{}
	if !reflect.DeepEqual(InputStructure(), schema) {
		t.Fatal("bundle projection aliases child owner declarations")
	}
}

func TestBundleRecordedChildAgreesWithNativeAdmission(t *testing.T) {
	exitCode := jsonshape.OneOf(jsonshape.IntegerLiteral(0), jsonshape.IntegerLiteral(1))
	for _, raw := range []json.Number{"0", "1", "-0", "1.0", "2", "01", "1e0"} {
		input := bundleWireValue(t, validBundleInput(t))
		child := input["receiptAdmission"].(map[string]any)
		child["exitCode"] = raw
		if raw == "1" {
			child["report"].(map[string]any)["state"] = "failed"
			child["failures"] = []any{"failure"}
		}
		_, nativeErr := optionalChild(child, "receipt admission", "proofkit.proof-receipt-admission")
		structural := exitCode.CheckGenerated(raw, "exitCode") == nil
		if raw == "1" {
			// A forged failed state passes structure but not owner recomputation.
			if !structural || nativeErr == nil || !strings.Contains(nativeErr.Error(), "owner validator") {
				t.Fatalf("exit 1 structure/native boundary drifted: %v", nativeErr)
			}
			continue
		}
		if (nativeErr == nil) != structural {
			t.Fatalf("exit code %s diverged: native=%v structural=%t", raw, nativeErr, structural)
		}
	}
	for name, mutate := range map[string]func(child map[string]any){
		"missing-report":      func(child map[string]any) { delete(child, "report") },
		"null-report":         func(child map[string]any) { child["report"] = nil },
		"missing-failures":    func(child map[string]any) { delete(child, "failures") },
		"object-failures":     func(child map[string]any) { child["failures"] = map[string]any{} },
		"missing-producers":   func(child map[string]any) { delete(child, "producers") },
		"scalar-producer":     func(child map[string]any) { child["producers"] = []any{"producer"} },
		"missing-receipts":    func(child map[string]any) { delete(child, "receipts") },
		"empty-receipts":      func(child map[string]any) { child["receipts"] = []any{} },
		"missing-nonclaims":   func(child map[string]any) { delete(child, "nonClaims") },
		"blank-nonclaim":      func(child map[string]any) { child["nonClaims"] = []any{" "} },
		"missing-exit":        func(child map[string]any) { delete(child, "exitCode") },
		"unknown-member":      func(child map[string]any) { child["foreign"] = true },
		"producer-member":     func(child map[string]any) { child["receiptKinds"] = []any{} },
		"report-unknown":      func(child map[string]any) { child["report"].(map[string]any)["foreign"] = true },
		"report-kind":         func(child map[string]any) { child["report"].(map[string]any)["reportKind"] = reportKind },
		"report-version":      func(child map[string]any) { child["report"].(map[string]any)["schemaVersion"] = json.Number("2") },
		"report-id":           func(child map[string]any) { child["report"].(map[string]any)["reportId"] = "1bad" },
		"passed-with-failure": func(child map[string]any) { child["failures"] = []any{"failure"} },
		"report-summary-forgery": func(child map[string]any) {
			child["report"].(map[string]any)["summary"].(map[string]any)["receiptCount"] = json.Number("2")
		},
	} {
		input := bundleWireValue(t, validBundleInput(t))
		mutate(input["receiptAdmission"].(map[string]any))
		if _, _, err := Build(input); err == nil {
			t.Fatalf("%s was admitted natively", name)
		}
	}
	for name, mutate := range map[string]func(child map[string]any){
		"missing-kinds":   func(child map[string]any) { delete(child, "receiptKinds") },
		"duplicate-kinds": func(child map[string]any) { child["receiptKinds"] = []any{"proofkit.go-test", "proofkit.go-test"} },
		"invalid-class":   func(child map[string]any) { child["environmentClasses"] = []any{"1bad"} },
		"missing-classes": func(child map[string]any) { delete(child, "environmentClasses") },
		"empty-nonclaims": func(child map[string]any) { child["nonClaims"] = []any{} },
		"scalar-producer": func(child map[string]any) { child["producers"] = []any{false} },
		"wrong-report-kind": func(child map[string]any) {
			child["report"].(map[string]any)["reportKind"] = "proofkit.proof-receipt-admission"
		},
	} {
		input := bundleWireValue(t, validMergeBundleInput(t))
		mutate(input["receiptProducerAdmission"].(map[string]any))
		if _, _, err := Build(input); err == nil {
			t.Fatalf("producer %s was admitted natively", name)
		}
	}
	for name, mutate := range map[string]func(input map[string]any){
		"ignored-producer-rows": func(input map[string]any) {
			input["receiptAdmission"].(map[string]any)["producers"] = []any{map[string]any{"any": []any{nil}}, map[string]any{}}
		},
		"opaque-failures-on-failed-child": func(input map[string]any) {
			receipt := validProofReceipt()
			receipt["finishedAt"] = "2026-06-21T00:00:00Z"
			child := bundleWireValue(t, proofReceiptChild(t, []any{receipt}))
			child["failures"] = []any{nil, false, json.Number("1"), []any{}, map[string]any{}}
			input["receiptAdmission"] = child
		},
		"unsorted-producer-vocabulary": func(input map[string]any) {
			input["receiptProducerAdmission"] = bundleWireValue(t, producerAdmissionChild(t, []any{validProducer()}, []any{validProducerReceipt()},
				[]any{"proofkit.extra", "proofkit.go-test"}, []any{"local-alpha", "local-go"}))
			child := input["receiptProducerAdmission"].(map[string]any)
			child["receiptKinds"], child["environmentClasses"] = []any{"proofkit.go-test", "proofkit.extra"}, []any{"local-go", "local-alpha"}
		},
	} {
		input := bundleWireValue(t, validMergeBundleInput(t))
		mutate(input)
		if _, _, err := Build(input); err != nil {
			t.Fatalf("%s was refused natively: %v", name, err)
		}
	}
}

func TestBundleOwnMembersAgreeWithNativeAdmission(t *testing.T) {
	schema := InputStructure()
	properties := schema["properties"].(map[string]any)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	if !reflect.DeepEqual(properties["bundleId"], nestedSchema(id)) || properties["mergeRequiredReceiptIds"].(map[string]any)["uniqueItems"] != true {
		t.Fatal("bundle identity structures drifted")
	}
	shapes := map[string]jsonshape.Shape{
		"bundleId": id, "mergeRequiredReceiptIds": jsonshape.Array(id, 0),
		"nonClaims": jsonshape.Array(jsonshape.NonBlankString(), 0), "schemaVersion": jsonshape.IntegerLiteral(1),
	}
	for key, shape := range shapes {
		if !reflect.DeepEqual(properties[key].(map[string]any)["type"], nestedSchema(shape)["type"]) {
			t.Fatalf("%s type drifted", key)
		}
	}
	for _, test := range []struct {
		key   string
		value any
		want  bool
	}{
		{"bundleId", strings.Repeat("a", admit.MaxRuleIDBytes), true}, {"bundleId", strings.Repeat("a", admit.MaxRuleIDBytes+1), false},
		{"bundleId", " padded", false}, {"schemaVersion", json.Number("1.0"), false}, {"schemaVersion", "1", false},
		{"nonClaims", []any{" padded duplicate", "padded duplicate"}, true}, {"nonClaims", []any{}, true}, {"nonClaims", []any{" "}, false},
		{"nonClaims", nil, false}, {"mergeRequiredReceiptIds", []any{"bad id"}, false}, {"mergeRequiredReceiptIds", nil, false},
	} {
		input := bundleWireValue(t, validBundleInput(t))
		input[test.key] = test.value
		_, _, nativeErr := Build(input)
		structural := shapes[test.key].CheckGenerated(test.value, test.key) == nil
		if (nativeErr == nil) != test.want || structural != test.want {
			t.Fatalf("%s=%v diverged: native=%v structural=%t", test.key, test.value, nativeErr, structural)
		}
	}
	input := bundleWireValue(t, validBundleInput(t))
	input["mergeRequiredReceiptIds"] = []any{"receipt.test.one", "receipt.test.one"}
	if _, _, err := Build(input); err == nil {
		t.Fatal("duplicate merge-required receipt IDs admitted natively")
	}
	for _, key := range inputKeys {
		missing := bundleWireValue(t, validBundleInput(t))
		delete(missing, key)
		_, _, err := Build(missing)
		optional := key == "receiptAdmission" || key == "receiptProducerAdmission"
		if (err == nil) != optional || slices.Contains(schema["required"].([]any), any(key)) == optional {
			t.Fatalf("%s requiredness diverged: %v", key, err)
		}
	}
}

func bundleChildren(value map[string]any) map[string]any {
	return value["diagnostics"].([]any)[0].(map[string]any)["value"].(map[string]any)
}

func bundleWireValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
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
