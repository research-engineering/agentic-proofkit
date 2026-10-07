package adoptionmaterialization

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func TestMaterializationInputStructurePreservesNativeRequest(t *testing.T) {
	shape, err := InputShape()
	if err != nil {
		t.Fatal(err)
	}
	wire := jsonRoundTripValue(t, validRequest(t, t.TempDir())).(map[string]any)
	wire["nonClaims"] = []any{}
	if _, err := admitRequest(wire); err != nil {
		t.Fatal(err)
	}
	assertMaterializationStructure(t, shape, wire, nil)
	for _, count := range []int{0, 1, 29, 30} {
		candidate := maps.Clone(wire)
		sources := make([]any, count)
		for i := range sources {
			sources[i] = wire["requirementSources"].([]any)[0]
		}
		candidate["requirementSources"] = sources
		_, err := shape.Admit(candidate, "request")
		if (err == nil) != (count >= 1 && count <= 29) {
			t.Fatalf("source count %d: %v", count, err)
		}
	}
	// These are shape endpoints, not a claim that duplicate sources pass native closure.
	for _, field := range []string{"projectId", "requestId"} {
		for _, value := range []string{"A", "0", "project_A-1.x", strings.Repeat("a", 256), "", "a/b", " a", "a ", strings.Repeat("a", 257)} {
			candidate := maps.Clone(wire)
			candidate[field] = value
			_, err := shape.Admit(candidate, "request")
			want := value == "A" || value == "project_A-1.x" || len(value) == 256
			if (err == nil) != want {
				t.Fatalf("%s length %d: %v", field, len(value), err)
			}
		}
	}
	for _, field := range []string{"requirementProofBinding", "testEvidenceInventory"} {
		child := wire[field].(map[string]any)
		for _, mutation := range []string{"missing-path", "missing-record", "extra", "padded-path"} {
			candidate := maps.Clone(wire)
			changed := maps.Clone(child)
			switch mutation {
			case "missing-path":
				delete(changed, "path")
			case "missing-record":
				delete(changed, "record")
			case "extra":
				changed["foreign"] = true
			case "padded-path":
				changed["path"] = " " + child["path"].(string)
			}
			candidate[field] = changed
			if _, err := shape.Admit(candidate, "request"); err == nil {
				t.Fatalf("accepted %s/%s", field, mutation)
			}
		}
	}
}

func TestMaterializationStructuresPreserveExecutedPlanAndReceipts(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	request["nonClaims"] = []any{}
	plan, err := BuildPlan(t.Context(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	wire := jsonRoundTripValue(t, plan.JSONValue()).(map[string]any)
	if len(wire["nonClaims"].([]any)) != 4 {
		t.Fatal("empty caller claims did not retain exactly four built-in boundaries")
	}
	assertMaterializationStructure(t, PlanOutputShape(), wire, nil)
	if _, err := AdmitPlanOutput(wire); err != nil {
		t.Fatal(err)
	}
	apply, exit, err := Apply(t.Context(), request, root, plan.Transaction.TransactionID, plan.Transaction.DesiredStateID)
	if err != nil || exit != 0 {
		t.Fatalf("Apply: %d %v", exit, err)
	}
	recover, exit, err := Recover(t.Context(), root, plan.Transaction.TransactionID, repositorytransaction.RecoveryResume)
	if err != nil || exit != 0 {
		t.Fatalf("Recover: %d %v", exit, err)
	}
	for _, receipt := range []Receipt{apply, recover} {
		shape, err := ReceiptOutputShape(receipt.Operation)
		if err != nil {
			t.Fatal(err)
		}
		value := jsonRoundTripValue(t, receipt.JSONValue()).(map[string]any)
		nullable := map[string]bool{"failureClass": true, "transactionResult": true}
		if receipt.Operation == OperationRecover {
			nullable["expectedDesiredStateId"] = true
		}
		assertMaterializationStructure(t, shape, value, nullable)
		if _, err := AdmitReceiptOutput(value); err != nil {
			t.Fatal(err)
		}
		other := OperationRecover
		if receipt.Operation == OperationRecover {
			other = OperationApply
		}
		foreign, err := ReceiptOutputShape(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := foreign.Admit(value, "receipt"); err == nil {
			t.Fatal("accepted receipt under the other operation's structure")
		}
	}
}

func TestMaterializationReceiptStructurePreservesEveryNativeState(t *testing.T) {
	tx := "sha256:" + strings.Repeat("a", 64)
	desired := "sha256:" + strings.Repeat("b", 64)
	for _, state := range []string{"blocked", "cleanup_required", "durability_unknown", "failed", "passed", "recovery_required"} {
		for _, operation := range []string{OperationApply, OperationRecover} {
			desiredID := desired
			if operation == OperationRecover {
				desiredID = ""
			}
			failure := "operation_failed"
			result := &repositorytransaction.Result{State: state, FailureClass: failure, TransactionID: tx}
			if operation == OperationRecover {
				result.RecoveredBy = repositorytransaction.RecoveryRollback
			}
			switch state {
			case ReceiptStateBlocked:
				result = nil
			case ReceiptStateFailed:
				result.State = repositorytransaction.StateRolledBack
				result.AppliedCountKnown = true
				if operation == OperationRecover {
					failure = ""
					result.State, result.FailureClass = repositorytransaction.StateAlreadySatisfied, ""
					result.RecoveredBy = ""
				}
			case ReceiptStatePassed:
				failure = ""
				result.State, result.FailureClass = repositorytransaction.StateApplied, ""
				result.AppliedCount, result.AppliedCountKnown = 1, true
				if operation == OperationRecover {
					result.RecoveredBy = repositorytransaction.RecoveryResume
				}
			}
			receipt, err := newReceipt(operation, state, failure, tx, desiredID, result, nil)
			if err != nil {
				t.Fatalf("%s/%s native receipt: %v", operation, state, err)
			}
			shape, err := ReceiptOutputShape(operation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := shape.Admit(jsonRoundTripValue(t, receipt.JSONValue()), "receipt"); err != nil {
				t.Fatalf("%s/%s structure: %v", operation, state, err)
			}
		}
	}
	if _, err := ReceiptOutputShape("plan"); err == nil {
		t.Fatal("accepted non-receipt operation")
	}
}

func assertMaterializationStructure(t *testing.T, shape jsonshape.Shape, wire map[string]any, nullable map[string]bool) {
	t.Helper()
	if _, err := shape.Admit(wire, "materialization"); err != nil {
		t.Fatal(err)
	}
	for field := range wire {
		missing := maps.Clone(wire)
		delete(missing, field)
		if _, err := shape.Admit(missing, "materialization"); err == nil {
			t.Fatalf("accepted missing %s", field)
		}
		if !nullable[field] {
			null := maps.Clone(wire)
			null[field] = nil
			if _, err := shape.Admit(null, "materialization"); err == nil {
				t.Fatalf("accepted null %s", field)
			}
		}
	}
	for field, value := range map[string]any{"schemaVersion": json.Number("99"), "nonClaims": []any{"only one boundary"}, "foreign": true} {
		if field == "nonClaims" && wire["requestKind"] == RequestKind {
			continue
		}
		candidate := maps.Clone(wire)
		candidate[field] = value
		if _, err := shape.Admit(candidate, "materialization"); err == nil {
			t.Fatalf("accepted changed %s", field)
		}
	}
}
