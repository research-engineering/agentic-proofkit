package specproofbundleadmission

import (
	"slices"
	"sort"
	"testing"
)

func TestBundleReceiptEnvironmentIsBoundToItsWitnessCommand(t *testing.T) {
	for _, environment := range []string{"local-go", "local-go-python", "unplanned-environment"} {
		t.Run(environment, func(t *testing.T) {
			input := validMergeBundleInput(t)
			for _, raw := range input["witnessPlan"].(map[string]any)["commands"].([]any) {
				command := raw.(map[string]any)
				if command["id"] == "proofkit.go-test" {
					command["environment"].(map[string]any)["classes"] = []any{"local-go", "local-go-python"}
				}
			}
			for _, raw := range input["requirementBindings"].(map[string]any)["bindings"].([]any) {
				binding := raw.(map[string]any)
				for _, command := range binding["commandIds"].([]any) {
					if command == "proofkit.go-test" {
						values := binding["environmentClasses"].([]any)
						if !slices.Contains(values, any("local-go-python")) {
							values = append(values, "local-go-python")
						}
						sort.Slice(values, func(i, j int) bool { return values[i].(string) < values[j].(string) })
						binding["environmentClasses"] = values
					}
				}
			}
			receipt, producerReceipt, producer := mergeProofReceipt(), validProducerReceipt(), validProducer()
			receipt["environmentClass"] = environment
			producerReceipt["environmentClass"] = environment
			producer["environmentClasses"] = []any{environment}
			input["receiptAdmission"] = proofReceiptChild(t, []any{receipt})
			input["receiptProducerAdmission"] = producerAdmissionChild(t, []any{producer}, []any{producerReceipt}, []any{"proofkit.go-test"}, []any{environment})
			record, exit, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			if environment == "unplanned-environment" {
				if exit != 1 || record.State != "failed" {
					t.Fatal("coherent receipt/producer pair bypassed command environment")
				}
				assertFailedRuleMessage(t, record.RuleResults, "proofkit.spec-proof-bundle-admission.failure.", "environmentClass must match its witness-plan command")
			} else if exit != 0 || record.State != "passed" {
				t.Fatalf("allowed multi-environment receipt rejected: %s %d %#v", record.State, exit, record.RuleResults)
			}
		})
	}
}

func TestBundleAccumulatesAllWitnessesOfOneScenario(t *testing.T) {
	const scenario = "proofkit.package-boundary.contract-map-table-shape"
	for _, reversed := range []bool{false, true} {
		for _, command := range []string{"proofkit.go-test", "proofkit.package-artifact", "proofkit.foreign-command"} {
			input := validBundleInput(t)
			file := input["requirementBindings"].(map[string]any)
			rows := append(file["bindings"].([]any), map[string]any{
				"commandIds": []any{"proofkit.package-artifact"}, "environmentClasses": []any{"local-go-python"},
				"requirementId": "REQ-PROOFKIT-PACKAGE-001", "scenarioId": scenario,
				"witnessId": "zzzz.extra.witness", "witnessKind": "contract", "witnessPath": "internal/app/cli_contract_test.go",
			})
			if reversed {
				slices.Reverse(rows)
			}
			file["bindings"] = rows
			receipt := validProofReceipt()
			receipt["witnessSelectors"] = []any{scenario}
			receipt["receiptKind"] = command
			if command == "proofkit.package-artifact" {
				receipt["environmentClass"] = "local-go-python"
			}
			input["receiptAdmission"] = proofReceiptChild(t, []any{receipt})
			record, exit, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			if command == "proofkit.foreign-command" {
				if exit != 1 || record.State != "failed" {
					t.Fatal("foreign command satisfied a declared scenario")
				}
			} else if exit != 0 || record.State != "passed" {
				t.Fatalf("lost witness membership: reversed=%v command=%s failures=%#v", reversed, command, record.RuleResults)
			}
		}
	}
}
