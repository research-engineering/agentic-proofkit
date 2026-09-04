package adoptionmaterialization

import (
	"fmt"
	"strings"
)

func RenderPlanText(plan Plan) (string, error) {
	lines := []string{
		"Adoption materialization plan",
		"State: ready",
		"Project: " + plan.ProjectID,
		"Transaction: " + plan.Transaction.TransactionID,
		fmt.Sprintf("Operations: %d", len(plan.Transaction.Operations)),
	}
	for _, operation := range plan.Transaction.Operations {
		lines = append(lines, fmt.Sprintf("- %s %s", operation.Action, operation.Path))
	}
	return boundedText(lines)
}

func RenderReceiptText(receipt Receipt) (string, error) {
	lines := []string{
		"Adoption materialization receipt",
		"Operation: " + receipt.Operation,
		"State: " + receipt.State,
	}
	if receipt.ExpectedTransactionID != "" {
		lines = append(lines, "Expected transaction: "+receipt.ExpectedTransactionID)
	}
	if receipt.ExpectedDesiredStateID != "" {
		lines = append(lines, "Expected desired state: "+receipt.ExpectedDesiredStateID)
	}
	if receipt.FailureClass != "" {
		lines = append(lines, "Failure: "+receipt.FailureClass)
	}
	if receipt.TransactionResult != nil {
		lines = append(lines, "Transaction state: "+receipt.TransactionResult.State)
		if receipt.TransactionResult.AppliedCountKnown {
			lines = append(lines, fmt.Sprintf("Applied: %d", receipt.TransactionResult.AppliedCount))
		}
		if receipt.TransactionResult.RecoveredBy != "" {
			lines = append(lines, "Recovery: "+receipt.TransactionResult.RecoveredBy)
		}
	}
	return boundedText(lines)
}

func boundedText(lines []string) (string, error) {
	if len(lines) > MaximumTextLines {
		return "", fmt.Errorf("adoption materialization text exceeds its line limit")
	}
	text := strings.Join(lines, "\n") + "\n"
	if len(text) > MaximumTextBytes {
		return "", fmt.Errorf("adoption materialization text exceeds its byte limit")
	}
	return text, nil
}
