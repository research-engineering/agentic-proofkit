package agentintegration

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

type LifecyclePlan struct {
	document              Document
	operation             string
	state                 string
	failure               string
	recoveryTransactionID string
	transaction           *repositorytransaction.Plan
}

type LifecycleReceipt struct {
	tool                   string
	operation              string
	state                  string
	failure                string
	expectedTransactionID  string
	expectedDesiredStateID string
	result                 *repositorytransaction.Result
}

func (plan LifecyclePlan) ExitCode() int {
	if plan.state == "ready" {
		return 0
	}
	return 1
}

func (receipt LifecycleReceipt) ExitCode() int {
	if receipt.state == "passed" {
		return 0
	}
	return 1
}

func (plan LifecyclePlan) JSONValue() map[string]any {
	var child any
	if plan.transaction != nil {
		child = plan.transaction.JSONValue()
	}
	return map[string]any{
		"kind": "proofkit.integration-plan.v1", "schemaVersion": json.Number("1"),
		"tool": plan.document.tool, "operation": plan.operation, "state": plan.state,
		"failureClass":          lifecycleNullable(plan.failure),
		"recoveryTransactionId": lifecycleNullable(plan.recoveryTransactionID),
		"transaction":           child, "nonClaims": lifecycleNonClaims(),
	}
}

func (receipt LifecycleReceipt) JSONValue() map[string]any {
	var child any
	if receipt.result != nil {
		child = receipt.result.JSONValue()
	}
	return map[string]any{
		"kind": "proofkit.integration-receipt.v1", "schemaVersion": json.Number("1"),
		"tool": lifecycleNullable(receipt.tool), "operation": receipt.operation, "state": receipt.state,
		"failureClass":           lifecycleNullable(receipt.failure),
		"expectedTransactionId":  receipt.expectedTransactionID,
		"expectedDesiredStateId": lifecycleNullable(receipt.expectedDesiredStateID),
		"transactionResult":      child, "nonClaims": lifecycleNonClaims(),
	}
}

func (receipt LifecycleReceipt) withResult(result repositorytransaction.Result) LifecycleReceipt {
	receipt.result, receipt.failure = &result, result.FailureClass
	switch result.State {
	case repositorytransaction.StateApplied, repositorytransaction.StateAlreadySatisfied:
		receipt.state = "passed"
	case repositorytransaction.StateRolledBack:
		receipt.state = "failed"
		if receipt.operation == OperationRecover {
			receipt.state = "passed"
		}
	case repositorytransaction.StateCleanupRequired, repositorytransaction.StateDurabilityUnknown, repositorytransaction.StateRecoveryRequired:
		receipt.state = result.State
	default:
		receipt.state = "failed"
	}
	return receipt
}

func (plan LifecyclePlan) Text() string {
	text := fmt.Sprintf("Integration plan: %s\nTool: %s\nOperation: %s\n", plan.state, plan.document.tool, plan.operation)
	if plan.transaction != nil {
		text += fmt.Sprintf("Transaction: %s\nDesired state: %s\n", plan.transaction.TransactionID, plan.transaction.DesiredStateID)
		for _, operation := range plan.transaction.Operations {
			text += fmt.Sprintf("%s %s\n", operation.Action, operation.Path)
		}
	}
	if plan.failure != "" {
		text += "Reason: " + plan.failure + "\n"
	}
	if plan.recoveryTransactionID != "" {
		text += "Pending transaction: " + plan.recoveryTransactionID + "\n"
	}
	return text + "File lifecycle only; baseline is cooperative bookkeeping, not authenticated origin or host activation.\n"
}

func (receipt LifecycleReceipt) Text() string {
	text := fmt.Sprintf("Integration %s: %s\nTransaction: %s\n", receipt.operation, receipt.state, receipt.expectedTransactionID)
	if receipt.failure != "" {
		text += "Reason: " + receipt.failure + "\n"
	}
	return text + "Recovery is historical; no current host activation or post-return file stability is proven.\n"
}

func lifecycleNullable(text string) any {
	if text == "" {
		return nil
	}
	return text
}

func lifecycleNonClaims() []any {
	return []any{
		"A baseline is cooperative snapshot bookkeeping, not authenticated origin, owner approval, or protection from coordinated same-user edits or rollback.",
		"File lifecycle operations do not prove native host discovery, loading, invocation, semantic correctness, merge approval, or production readiness.",
		"Recovery results describe a historical transaction, not current installed or removed state; observations do not guarantee post-return stability.",
	}
}
