package agentintegration

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func testLifecycleTerminalResultProjection(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	desired := "sha256:" + strings.Repeat("b", 64)
	for _, test := range []struct {
		native, apply, recover, failure string
		known                           bool
		count                           int
	}{
		{"applied", "passed", "passed", "", true, 2},
		{"already_satisfied", "passed", "passed", "", true, 0},
		{"rolled_back", "failed", "passed", "cancelled", true, 0},
		{"cleanup_required", "cleanup_required", "cleanup_required", "cleanup_failed", true, 2},
		{"durability_unknown", "durability_unknown", "durability_unknown", "applied_cleanup_durability_unknown", true, 2},
		{"recovery_required", "recovery_required", "recovery_required", "ambiguous_target_state", false, 0},
	} {
		for _, operation := range []string{OperationInstall, OperationUpdate, OperationRemove, OperationRecover} {
			t.Run(test.native+"/"+operation, func(t *testing.T) {
				seed := LifecycleReceipt{tool: "codex", operation: operation, expectedTransactionID: id, expectedDesiredStateID: desired}
				want, recoveredBy := test.apply, ""
				var tool, desiredValue any = "codex", desired
				if operation == OperationRecover {
					seed.tool, seed.expectedDesiredStateID = "", ""
					want, recoveredBy, tool, desiredValue = test.recover, "resume", nil, nil
					if test.native == "rolled_back" {
						recoveredBy = "rollback"
					}
				}
				native := repositorytransaction.Result{State: test.native, FailureClass: test.failure, AppliedCount: test.count, AppliedCountKnown: test.known, TransactionID: id, RecoveredBy: recoveredBy}
				receipt, err := applyLifecycleResult(seed, native, nil)
				if err != nil || receipt.result == nil || *receipt.result != native {
					t.Fatalf("native result lost: %#v %v", receipt, err)
				}
				value := receipt.JSONValue()
				var failure, count, recovery any
				if test.failure != "" {
					failure = test.failure
				}
				if test.known {
					count = json.Number(fmt.Sprint(test.count))
				}
				if recoveredBy != "" {
					recovery = recoveredBy
				}
				if len(value) != 10 || value["kind"] != "proofkit.integration-receipt.v1" || value["schemaVersion"] != json.Number("1") || value["tool"] != tool || value["operation"] != operation || value["state"] != want || value["failureClass"] != failure || value["expectedTransactionId"] != id || value["expectedDesiredStateId"] != desiredValue || !reflect.DeepEqual(value["nonClaims"], lifecycleNonClaims()) {
					t.Fatal("parent state, identity or failure projection changed")
				}
				child, ok := value["transactionResult"].(map[string]any)
				if !ok || len(child) != 7 || child["state"] != test.native || child["appliedCount"] != count || child["failureClass"] != failure || child["recoveredBy"] != recovery || child["transactionId"] != id || child["schemaVersion"] != json.Number("1") {
					t.Fatal("native child fields were dropped or rewritten")
				}
				if !reflect.DeepEqual(child, native.JSONValue()) {
					t.Fatal("parent no longer retains the complete child-owned projection")
				}
				wantCode := 1
				if want == "passed" {
					wantCode = 0
				}
				text := fmt.Sprintf("Integration %s: %s\nTransaction: %s\n", operation, want, id)
				if test.failure != "" {
					text += "Reason: " + test.failure + "\n"
				}
				text += "Recovery is historical; no current host activation or post-return file stability is proven.\n"
				if receipt.ExitCode() != wantCode || receipt.Text() != text {
					t.Fatal("text or exit projection erased the terminal outcome")
				}
			})
		}
	}
}
