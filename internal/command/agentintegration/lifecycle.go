package agentintegration

import (
	"context"
	"errors"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

const (
	OperationInstall = "install"
	OperationUpdate  = "update"
	OperationRemove  = "remove"
	OperationRecover = "recover"
)

// PlanLifecycle recognizes only snapshots captured by the native transaction
// builder. The opaque result retains its executable plan privately.
func PlanLifecycle(ctx context.Context, root string, document Document, operation string) (LifecyclePlan, error) {
	if ctx == nil {
		return LifecyclePlan{}, fmt.Errorf("integration context is required")
	}
	if operation != OperationInstall && operation != OperationUpdate && operation != OperationRemove {
		return LifecyclePlan{}, fmt.Errorf("integration operation must be install, update or remove")
	}
	if document.tool == "" || document.path == "" || document.content == "" || document.contentDigest == "" || document.identity == "" {
		return LifecyclePlan{}, fmt.Errorf("integration source document is required")
	}
	baseline, err := currentBaseline(document)
	if err != nil {
		return LifecyclePlan{}, err
	}
	targets := []repositorytransaction.Target{
		{Path: document.path, Content: []byte(document.content), Mode: 0o644},
		{Path: baselinePath(document), Content: baseline, Mode: 0o644},
	}
	if operation == OperationRemove {
		for index := range targets {
			targets[index] = repositorytransaction.Target{Path: targets[index].Path, Absent: true}
		}
	}
	plan := LifecyclePlan{document: document, operation: operation, state: "ready"}
	transaction, err := repositorytransaction.BuildPlan(ctx, root, targets)
	if err != nil {
		if errors.Is(err, repositorytransaction.ErrRecoveryRequired) {
			plan.state, plan.failure = "recovery_required", "pending_transaction_state"
			plan.recoveryTransactionID, _ = repositorytransaction.RecoveryTransactionID(err)
			return plan, nil
		}
		if errors.Is(err, repositorytransaction.ErrBusy) {
			plan.state, plan.failure = "blocked", "transaction_busy"
			return plan, nil
		}
		return LifecyclePlan{}, err
	}
	if conflict := recognizeLifecyclePair(document, operation, transaction); conflict != "" {
		plan.state, plan.failure = "blocked", conflict
		return plan, nil
	}
	plan.transaction = &transaction
	return plan, nil
}

func ApplyLifecycle(ctx context.Context, root string, document Document, operation, expectedTransaction, expectedDesired string) (LifecycleReceipt, error) {
	expected, err := admit.SHA256Ref(expectedTransaction, "integration expected transaction")
	if err != nil {
		return LifecycleReceipt{}, err
	}
	desired, err := admit.SHA256Ref(expectedDesired, "integration expected desired state")
	if err != nil {
		return LifecycleReceipt{}, err
	}
	plan, err := PlanLifecycle(ctx, root, document, operation)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	receipt := LifecycleReceipt{tool: document.tool, operation: operation, expectedTransactionID: expected, expectedDesiredStateID: desired, state: plan.state, failure: plan.failure}
	if plan.state != "ready" {
		if plan.state == "recovery_required" {
			result := repositorytransaction.Result{State: repositorytransaction.StateRecoveryRequired, FailureClass: plan.failure, TransactionID: plan.recoveryTransactionID}
			receipt.result = &result
		}
		return receipt, nil
	}
	transaction := *plan.transaction
	if transaction.DesiredStateID != desired {
		receipt.state, receipt.failure = "blocked", "desired_state_identity_mismatch"
		return receipt, nil
	}
	var result repositorytransaction.Result
	if transaction.TransactionID != expected {
		if lifecycleHasChanges(transaction) {
			receipt.state, receipt.failure = "blocked", "transaction_identity_mismatch"
			return receipt, nil
		}
		result, err = repositorytransaction.ReplayApplied(ctx, root, transaction, expected)
	} else {
		result, err = repositorytransaction.Apply(ctx, root, transaction)
	}
	return applyLifecycleResult(receipt, result, err)
}

func applyLifecycleResult(receipt LifecycleReceipt, result repositorytransaction.Result, err error) (LifecycleReceipt, error) {
	if err != nil {
		switch {
		case errors.Is(err, repositorytransaction.ErrReadCleanup), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return LifecycleReceipt{}, err
		case errors.Is(err, repositorytransaction.ErrReplayMismatch):
			receipt.state, receipt.failure = "blocked", "transaction_identity_mismatch"
			return receipt, nil
		case errors.Is(err, repositorytransaction.ErrBusy):
			receipt.state, receipt.failure = "blocked", "transaction_busy"
			return receipt, nil
		case errors.Is(err, repositorytransaction.ErrRecoveryRequired):
			id, _ := repositorytransaction.RecoveryTransactionID(err)
			result = repositorytransaction.Result{State: repositorytransaction.StateRecoveryRequired, FailureClass: "pending_transaction_state", TransactionID: id}
		default:
			return LifecycleReceipt{}, err
		}
	}
	return receipt.withResult(result), nil
}

func RecoverLifecycle(ctx context.Context, root, transactionID, action string) (LifecycleReceipt, error) {
	if ctx == nil {
		return LifecycleReceipt{}, fmt.Errorf("integration context is required")
	}
	expected, err := admit.SHA256Ref(transactionID, "integration recovery transaction")
	if err != nil {
		return LifecycleReceipt{}, err
	}
	result, err := repositorytransaction.Recover(ctx, root, expected, action)
	receipt := LifecycleReceipt{operation: OperationRecover, expectedTransactionID: expected}
	if errors.Is(err, repositorytransaction.ErrBusy) {
		receipt.state, receipt.failure = "blocked", "transaction_busy"
		return receipt, nil
	}
	if err != nil {
		return LifecycleReceipt{}, err
	}
	return receipt.withResult(result), nil
}

func lifecycleHasChanges(transaction repositorytransaction.Plan) bool {
	for _, operation := range transaction.Operations {
		if operation.Action != repositorytransaction.ActionUnchanged {
			return true
		}
	}
	return false
}
