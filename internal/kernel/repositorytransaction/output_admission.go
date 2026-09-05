package repositorytransaction

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var resultStateSet = map[string]struct{}{
	StateApplied:           {},
	StateAlreadySatisfied:  {},
	StateCleanupRequired:   {},
	StateDurabilityUnknown: {},
	StateRecoveryRequired:  {},
	StateRolledBack:        {},
}

// AdmitPlanOutput validates the complete public projection of a repository
// transaction plan. The admitted result is descriptive and intentionally
// lacks native construction identity and private execution payloads.
func AdmitPlanOutput(raw any) (Plan, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Plan{}, fmt.Errorf("repository transaction plan must be an object")
	}
	if err := admit.KnownKeys(record, []string{"createdDirectories", "desiredStateId", "nonClaims", "operations", "rootId", "schemaVersion", "transactionId", "transactionKind"}, "repository transaction plan"); err != nil {
		return Plan{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["transactionKind"] != "proofkit.repository-write-plan" {
		return Plan{}, fmt.Errorf("repository transaction plan identity is invalid")
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "repository transaction plan nonClaims", false)
	if err != nil || !slices.Equal(nonClaims, boundaryNonClaims) {
		return Plan{}, fmt.Errorf("repository transaction plan nonClaims are invalid")
	}
	journal := map[string]any{
		"createdDirectories": record["createdDirectories"],
		"desiredStateId":     record["desiredStateId"],
		"journalKind":        "proofkit.repository-write-journal",
		"operations":         record["operations"],
		"rootId":             record["rootId"],
		"schemaVersion":      record["schemaVersion"],
		"transactionId":      record["transactionId"],
	}
	plan, err := admitJournal(journal)
	if err != nil {
		return Plan{}, err
	}
	actual, err := stablejson.Marshal(record)
	if err != nil {
		return Plan{}, fmt.Errorf("encode repository transaction plan")
	}
	expected, err := stablejson.Marshal(plan.JSONValue())
	if err != nil || !bytes.Equal(actual, expected) {
		return Plan{}, fmt.Errorf("repository transaction plan is not canonical")
	}
	return plan, nil
}

// AdmitResultOutput validates the public transaction-result state relation.
func AdmitResultOutput(raw any) (Result, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Result{}, fmt.Errorf("repository transaction result must be an object")
	}
	if err := admit.KnownKeys(record, []string{"appliedCount", "failureClass", "nonClaims", "recoveredBy", "schemaVersion", "state", "transactionId"}, "repository transaction result"); err != nil {
		return Result{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Result{}, fmt.Errorf("repository transaction result schemaVersion is invalid")
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "repository transaction result nonClaims", false)
	if err != nil || !slices.Equal(nonClaims, boundaryNonClaims) {
		return Result{}, fmt.Errorf("repository transaction result nonClaims are invalid")
	}
	state, err := admit.Enum(record["state"], resultStateSet, "repository transaction result state")
	if err != nil {
		return Result{}, err
	}
	result := Result{State: state}
	if record["appliedCount"] != nil {
		count, err := admit.CanonicalInteger(record["appliedCount"], "repository transaction result appliedCount")
		if err != nil || count < 0 || count > MaximumOperations {
			return Result{}, fmt.Errorf("repository transaction result appliedCount is invalid")
		}
		result.AppliedCount = int(count)
		result.AppliedCountKnown = true
	}
	if record["failureClass"] != nil {
		failureClass, err := admit.NonEmptyText(record["failureClass"], "repository transaction result failureClass")
		if err != nil {
			return Result{}, err
		}
		result.FailureClass = failureClass
	}
	if record["recoveredBy"] != nil {
		recoveredBy, err := admit.Enum(record["recoveredBy"], map[string]struct{}{RecoveryResume: {}, RecoveryRollback: {}}, "repository transaction result recoveredBy")
		if err != nil {
			return Result{}, err
		}
		result.RecoveredBy = recoveredBy
	}
	if record["transactionId"] != nil {
		transactionID, err := admit.SHA256Ref(record["transactionId"], "repository transaction result transactionId")
		if err != nil {
			return Result{}, err
		}
		result.TransactionID = transactionID
	}
	if err := validateResultRelation(result); err != nil {
		return Result{}, err
	}
	actual, err := stablejson.Marshal(record)
	if err != nil {
		return Result{}, fmt.Errorf("encode repository transaction result")
	}
	expected, err := stablejson.Marshal(result.JSONValue())
	if err != nil || !bytes.Equal(actual, expected) {
		return Result{}, fmt.Errorf("repository transaction result is not canonical")
	}
	return result, nil
}

func validateResultRelation(result Result) error {
	if result.TransactionID == "" && (result.AppliedCountKnown || result.RecoveredBy != "") {
		return fmt.Errorf("repository transaction progress requires a transaction identity")
	}
	switch result.State {
	case StateApplied:
		if !result.AppliedCountKnown || result.AppliedCount == 0 || result.TransactionID == "" || result.FailureClass != "" || result.RecoveredBy == RecoveryRollback {
			return fmt.Errorf("applied repository transaction result is inconsistent")
		}
	case StateAlreadySatisfied:
		if !result.AppliedCountKnown || result.AppliedCount != 0 || result.TransactionID == "" || result.FailureClass != "" || result.RecoveredBy != "" {
			return fmt.Errorf("already-satisfied repository transaction result is inconsistent")
		}
	case StateRolledBack:
		if !result.AppliedCountKnown || result.AppliedCount != 0 || result.TransactionID == "" || result.RecoveredBy == RecoveryResume || result.RecoveredBy == "" && result.FailureClass == "" {
			return fmt.Errorf("rolled-back repository transaction result is inconsistent")
		}
	case StateCleanupRequired, StateDurabilityUnknown:
		if result.FailureClass == "" || result.TransactionID == "" {
			return fmt.Errorf("cleanup-pending repository transaction result is inconsistent")
		}
	case StateRecoveryRequired:
		if result.FailureClass == "" {
			return fmt.Errorf("non-terminal repository transaction result requires a failure class")
		}
	}
	return nil
}
