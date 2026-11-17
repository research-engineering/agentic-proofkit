package gradualadoption

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestGuidanceSourcePartitionsSurviveActionConstruction(t *testing.T) {
	for _, count := range []int{1, 2, 3, 4, 5, 7, 8, 9} {
		for _, reverse := range []bool{false, true} {
			for _, carrier := range []string{"report", "envelope"} {
				t.Run(fmt.Sprintf("%d/reverse=%t/%s", count, reverse, carrier), func(t *testing.T) {
					input := guidanceInput("observe")
					failed := make([]string, count)
					rules := []any{map[string]any{"ruleId": "rule.a", "status": "warning"}}
					for index := range count {
						failed[index] = fmt.Sprintf("rule.%c", 'b'+index)
						rules = append(rules, map[string]any{"ruleId": failed[index], "status": "failed"})
					}
					if reverse {
						slices.Reverse(rules)
					}
					source := input["sourceReport"].(map[string]any)
					source["state"], source["ruleResults"] = "failed", rules
					input["agentGuidance"].(map[string]any)["requiredNextActions"] = []any{"Inspect failed source rules."}
					input = g1WireInput(t, input)
					var output map[string]any
					var code int
					var err error
					if carrier == "report" {
						output, code, err = BuildGuidance(input, GuidanceOptions{})
					} else {
						output, code, err = BuildGuidanceEnvelope(input, GuidanceOptions{})
					}
					if err != nil || code != 0 {
						t.Fatalf("observe failed: exit=%d err=%v", code, err)
					}
					if carrier == "report" {
						guidance := diagnosticValue(t, output, "guidance").(map[string]any)
						if !reflect.DeepEqual(guidance["sourceFailedRuleIds"], admit.StringSliceToAny(failed)) || !reflect.DeepEqual(guidance["sourceWarningRuleIds"], []any{"rule.a"}) {
							t.Fatalf("source partitions changed: failed=%v warning=%v want failed=%v warning=[rule.a]", guidance["sourceFailedRuleIds"], guidance["sourceWarningRuleIds"], failed)
						}
						for _, raw := range guidance["agentActionPlan"].([]any) {
							action := raw.(map[string]any)
							if action["phase"] == "verify" && !reflect.DeepEqual(action["evidenceRefs"], admit.StringSliceToAny(append([]string{"rule.a"}, failed...))) {
								t.Fatal("verify evidence lost a source rule")
							}
						}
					} else {
						if got := g1EnvelopeRuleRefs(output, "source-failure"); !reflect.DeepEqual(got, failed) {
							t.Fatalf("failure contexts=%v want %v", got, failed)
						}
						if got := g1EnvelopeRuleRefs(output, "source-warning"); !reflect.DeepEqual(got, []string{"rule.a"}) {
							t.Fatalf("warning contexts=%v", got)
						}
					}
				})
			}
		}
	}
}

func TestGuidanceUnattributedFailureIsNotARule(t *testing.T) {
	for _, mode := range []string{"observe", "warn", "enforce-touched", "enforce-all"} {
		for _, touched := range [][]string{{}, {"rule.real"}, {"report.parent"}} {
			t.Run(mode+"/"+strings.Join(touched, ","), func(t *testing.T) {
				input := guidanceInput(mode)
				source := input["sourceReport"].(map[string]any)
				source["state"], source["reportId"] = "failed", "report.parent"
				// The report ID may coincide with a real touched warning rule, not a failed rule.
				source["ruleResults"] = []any{map[string]any{"ruleId": "report.parent", "status": "warning"}}
				scope := input["scopeEvidence"].(map[string]any)
				scope["touchedRuleIds"] = admit.StringSliceToAny(touched)
				if mode == "enforce-touched" {
					scope["checkedScope"] = "touched"
				}
				input["agentGuidance"].(map[string]any)["requiredNextActions"] = []any{"Inspect the unattributed source report failure."}
				output, code, err := BuildGuidance(g1WireInput(t, input), GuidanceOptions{})
				wantCode := 0
				if strings.HasPrefix(mode, "enforce-") {
					wantCode = 1
				}
				if err != nil || code != wantCode {
					t.Fatalf("report policy exit=%d err=%v want=%d", code, err, wantCode)
				}
				guidance := diagnosticValue(t, output, "guidance").(map[string]any)
				if got := guidance["sourceFailedRuleIds"].([]any); len(got) != 0 {
					t.Errorf("invented failed rule: %v", got)
				}
				summary := output["summary"].(map[string]any)
				if summary["sourceFailedRuleCount"] != 0 || summary["sourceReportState"] != "failed" {
					t.Errorf("report state/failed count lost: %v", summary)
				}
				envelope, envelopeCode, err := BuildGuidanceEnvelope(g1WireInput(t, input), GuidanceOptions{})
				if err != nil || envelopeCode != wantCode || len(g1EnvelopeRuleRefs(envelope, "source-failure")) != 0 {
					t.Errorf("phantom failure context or wrong envelope policy: exit=%d err=%v refs=%v", envelopeCode, err, g1EnvelopeRuleRefs(envelope, "source-failure"))
				}
			})
		}
	}
	for _, touched := range []string{"rule.inside", "rule.outside"} {
		input := guidanceInput("enforce-touched")
		input["scopeEvidence"].(map[string]any)["checkedScope"] = "touched"
		input["scopeEvidence"].(map[string]any)["touchedRuleIds"] = []any{touched}
		source := input["sourceReport"].(map[string]any)
		source["state"] = "failed"
		source["ruleResults"] = []any{map[string]any{"ruleId": "rule.inside", "status": "failed"}}
		input["agentGuidance"].(map[string]any)["requiredNextActions"] = []any{"Inspect attributed failure."}
		_, code, err := BuildGuidance(input, GuidanceOptions{})
		wantCode := 0
		if touched == "rule.inside" {
			wantCode = 1
		}
		if err != nil || code != wantCode {
			t.Fatalf("attributed touched-scope policy changed: %s exit=%d err=%v", touched, code, err)
		}
	}
}

func TestGuidanceOptionsAndJSONShareRuleIDAdmission(t *testing.T) {
	for _, ids := range [][]string{{"not a rule id"}, {"rule.valid"}, {"rule.z", "rule.a"}, {"rule.same", "rule.same"}} {
		t.Run(strings.Join(ids, ","), func(t *testing.T) {
			input := guidanceInput("observe")
			input["scopeEvidence"].(map[string]any)["checkedScope"] = "touched"
			input["scopeEvidence"].(map[string]any)["touchedRuleIds"] = admit.StringSliceToAny(ids)
			fromJSON, jsonCode, err := BuildGuidance(g1WireInput(t, input), GuidanceOptions{})
			if err != nil {
				t.Fatal(err)
			}
			input["scopeEvidence"].(map[string]any)["touchedRuleIds"] = []any{}
			before := slices.Clone(ids)
			fromOptions, optionsCode, err := BuildGuidance(input, GuidanceOptions{TouchedRuleIDs: ids})
			if err != nil || jsonCode != optionsCode || !reflect.DeepEqual(fromJSON, fromOptions) {
				t.Errorf("source-dependent admission: JSON exit=%d options exit=%d err=%v", jsonCode, optionsCode, err)
			}
			if !reflect.DeepEqual(ids, before) {
				t.Error("options slice mutated during admission")
			}
		})
	}
}

func TestGuidanceEmptyFailedReportRetainsReportPolicy(t *testing.T) {
	for _, mode := range []string{"observe", "warn", "enforce-touched", "enforce-all"} {
		for _, scope := range []string{"all", "touched", "none"} {
			for _, hasAction := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/action=%t", mode, scope, hasAction), func(t *testing.T) {
					input := guidanceInput(mode)
					input["sourceReport"].(map[string]any)["state"] = "failed"
					input["scopeEvidence"].(map[string]any)["checkedScope"] = scope
					if hasAction {
						input["agentGuidance"].(map[string]any)["requiredNextActions"] = []any{"Inspect the failed report."}
					}
					output, code, err := BuildGuidance(g1WireInput(t, input), GuidanceOptions{})
					wantCode := 0
					if !hasAction || strings.HasPrefix(mode, "enforce-") {
						wantCode = 1
					}
					if err != nil || code != wantCode {
						t.Fatalf("unattributed report policy exit=%d err=%v want=%d", code, err, wantCode)
					}
					guidance := diagnosticValue(t, output, "guidance").(map[string]any)
					if len(guidance["sourceFailedRuleIds"].([]any)) != 0 || output["summary"].(map[string]any)["sourceFailedRuleCount"] != 0 {
						t.Fatal("empty ruleResults invented a failed rule")
					}
					if diagnosticValue(t, output, "sourceReport").(map[string]any)["state"] != "failed" {
						t.Fatal("unattributed source failure disappeared")
					}
				})
			}
		}
	}
}

func g1WireInput(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(input)
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

func g1EnvelopeRuleRefs(output map[string]any, namespace string) []string {
	refs := []string{}
	for _, raw := range output["contextRefs"].([]any) {
		ref := raw.(map[string]any)
		if strings.HasPrefix(ref["refId"].(string), "proofkit.agent.context."+namespace+".") {
			refs = append(refs, ref["ref"].(string))
		}
	}
	return refs
}
