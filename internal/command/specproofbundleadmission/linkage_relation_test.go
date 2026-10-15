package specproofbundleadmission

import (
	"encoding/json"
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
			// The receipt ran under the edited go-test node, so it records that node.
			receipt["proofNodeDigest"] = admittedNodeDigests(input["witnessPlan"])["proofkit.go-test"]
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

func TestMinimumRuntimeRejectsAggregatePackageReceipt(t *testing.T) {
	for _, test := range []struct {
		name, kind, environment, want string
	}{
		{"aggregate package receipt", "proofkit.package-artifact", "local-go-python", "does not cover witness selector"},
		{"relabeled aggregate environment", "proofkit.python-minimum", "local-go-python", "environmentClass must match its witness-plan command"},
		{"separate advisory linkage only", "proofkit.python-minimum", "local-go-python-native-docker", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validBundleInput(t)
			receipt := validProofReceipt()
			receipt["receiptKind"], receipt["proofNodeDigest"] = test.kind, selfHostingNodeDigest(test.kind)
			receipt["environmentClass"] = test.environment
			receipt["witnessSelectors"] = []any{"proofkit.package-boundary.python-minimum-installed"}
			// Synthetic metadata only: neither this fixture nor the aggregate
			// package receipt is evidence of a native minimum-runtime execution.
			input["receiptAdmission"] = proofReceiptChild(t, []any{receipt})
			record, exit, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			if test.want == "" {
				if exit != 0 || record.State != "passed" {
					t.Fatalf("separate linkage rejected: %v", record.RuleResults)
				}
				return
			}
			if exit != 1 || record.State != "failed" {
				t.Fatal("aggregate receipt was promoted to minimum-runtime proof")
			}
			assertFailedRuleMessage(t, record.RuleResults, "proofkit.spec-proof-bundle-admission.failure.", test.want)
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
			if command != "proofkit.foreign-command" {
				receipt["proofNodeDigest"] = selfHostingNodeDigest(command)
			}
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

func planCommand(input map[string]any, commandID string) map[string]any {
	for _, raw := range input["witnessPlan"].(map[string]any)["commands"].([]any) {
		if command := raw.(map[string]any); command["id"] == commandID {
			return command
		}
	}
	panic("missing plan command " + commandID)
}

func planPolicy(input map[string]any, commandID string) map[string]any {
	for _, raw := range input["witnessPlan"].(map[string]any)["policies"].([]any) {
		if policy := raw.(map[string]any); policy["commandId"] == commandID {
			return policy
		}
	}
	panic("missing plan policy " + commandID)
}

// A receipt links only to the unchanged execution decision of its own plan
// node: an edit to that node unlinks exactly that receipt, while edits to
// other nodes, prose or spelling leave it linked. The plan ID is compared
// separately and is not part of the node digest.
func TestBundleLinkageBindsSchedulerPlanNode(t *testing.T) {
	const ownNodeChanged = "receipt receipt.test.one proofNodeDigest does not match witness scheduler plan node proofkit.go-test"
	for _, test := range []struct {
		name string
		edit func(map[string]any)
		want []string
	}{
		{"recorded node", func(map[string]any) {}, nil},
		{"same plan in another spelling", func(input map[string]any) {
			plan := input["witnessPlan"].(map[string]any)
			slices.Reverse(plan["commands"].([]any))
			slices.Reverse(plan["policies"].([]any))
			// An omitted optional list admits as the same empty list.
			delete(plan["vocabulary"].(map[string]any), "nonCacheableCredentialClasses")
		}, nil},
		{"another node's command and policy changed", func(input map[string]any) {
			planCommand(input, "proofkit.go-vet")["argv"] = []any{"go", "vet", "-all", "./..."}
			planPolicy(input, "proofkit.go-vet")["retryPolicy"] = map[string]any{"kind": "bounded", "maxAttempts": json.Number("2")}
		}, nil},
		{"plan and policy prose changed", func(input map[string]any) {
			plan := input["witnessPlan"].(map[string]any)
			plan["nonClaims"] = append(plan["nonClaims"].([]any), "zz Edited plan prose.")
			policy := planPolicy(input, "proofkit.go-test")
			policy["nonClaims"] = append(policy["nonClaims"].([]any), "zz Edited policy prose.")
		}, nil},
		{"same plan ID with changed own command", func(input map[string]any) {
			command := planCommand(input, "proofkit.go-test")
			command["argv"] = append(command["argv"].([]any), "-count=1")
		}, []string{ownNodeChanged}},
		{"same plan ID with changed own policy", func(input map[string]any) {
			planPolicy(input, "proofkit.go-test")["retryPolicy"] = map[string]any{"kind": "bounded", "maxAttempts": json.Number("2")}
		}, []string{ownNodeChanged}},
		{"same plan ID with changed own environment class row", func(input map[string]any) {
			for _, raw := range input["witnessPlan"].(map[string]any)["vocabulary"].(map[string]any)["environmentClassPolicies"].([]any) {
				if row := raw.(map[string]any); row["environmentClass"] == "local-go" {
					row["cachePolicies"] = []any{"disabled", "read-only"}
				}
			}
		}, []string{ownNodeChanged}},
		{"same node under another plan ID", func(input map[string]any) {
			input["witnessPlan"].(map[string]any)["schedulerPlanId"] = "proofkit.self-hosting.witness-plan.renamed"
		}, []string{"receipt receipt.test.one proofPlanId does not match witness scheduler plan"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validBundleInput(t)
			test.edit(input)
			record, exit, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, rule := range record.RuleResults {
				if rule.Status == "failed" {
					got = append(got, rule.Message)
				}
			}
			if len(test.want) == 0 {
				if exit != 0 || record.State != "passed" {
					t.Fatalf("receipt recorded under its unchanged node was unlinked: %v", got)
				}
				return
			}
			if exit != 1 || !slices.Equal(got, test.want) {
				t.Fatalf("failures = %v, want %v", got, test.want)
			}
		})
	}
}
