package adoptionmaterialization

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var receiptStateSet = map[string]struct{}{
	ReceiptStateBlocked:           {},
	ReceiptStateCleanupRequired:   {},
	ReceiptStateDurabilityUnknown: {},
	ReceiptStateFailed:            {},
	ReceiptStatePassed:            {},
	ReceiptStateRecoveryRequired:  {},
}

func AdmitPlanOutput(raw any) (Plan, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Plan{}, fmt.Errorf("adoption materialization plan must be an object")
	}
	if err := admit.KnownKeys(record, []string{"manifest", "nonClaims", "planKind", "projectId", "requestId", "schemaVersion", "sourceIntent", "sourcePlanId", "state", "transaction"}, "adoption materialization plan"); err != nil {
		return Plan{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["planKind"] != PlanKind || record["state"] != "ready" {
		return Plan{}, fmt.Errorf("adoption materialization plan identity is invalid")
	}
	projectID, err := admit.RuleID(record["projectId"], "adoption materialization plan projectId")
	if err != nil {
		return Plan{}, err
	}
	requestID, err := admit.RuleID(record["requestId"], "adoption materialization plan requestId")
	if err != nil {
		return Plan{}, err
	}
	sourcePlanID, err := admit.SHA256Ref(record["sourcePlanId"], "adoption materialization plan sourcePlanId")
	if err != nil {
		return Plan{}, err
	}
	sourceIntent, ok := record["sourceIntent"].(string)
	if !ok || !adoptionplan.IsIntent(sourceIntent) {
		return Plan{}, fmt.Errorf("adoption materialization plan sourceIntent is invalid")
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "adoption materialization plan nonClaims", false)
	if err != nil || !containsEvery(nonClaims, boundaryNonClaims) {
		return Plan{}, fmt.Errorf("adoption materialization plan nonClaims are invalid")
	}
	manifest, err := AdmitManifest(record["manifest"])
	if err != nil {
		return Plan{}, err
	}
	transaction, err := repositorytransaction.AdmitPlanOutput(record["transaction"])
	if err != nil {
		return Plan{}, err
	}
	if manifest.ProjectID != projectID || manifest.MaterializationRequestID != requestID || manifest.SourcePlanID != sourcePlanID {
		return Plan{}, fmt.Errorf("adoption materialization plan manifest identity is inconsistent")
	}
	if err := validatePlanRouteClosure(manifest, transaction); err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Manifest: manifest, NonClaims: nonClaims, ProjectID: projectID, RequestID: requestID,
		SourceIntent: sourceIntent, SourcePlanID: sourcePlanID, Transaction: transaction,
	}
	actual, err := stablejson.Marshal(record)
	if err != nil {
		return Plan{}, fmt.Errorf("encode adoption materialization plan")
	}
	expected, err := stablejson.Marshal(plan.JSONValue())
	if err != nil || !bytes.Equal(actual, expected) || len(actual) > MaximumOutputBytes {
		return Plan{}, fmt.Errorf("adoption materialization plan is not canonical")
	}
	return plan, nil
}

func AdmitReceiptOutput(raw any) (Receipt, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Receipt{}, fmt.Errorf("adoption materialization receipt must be an object")
	}
	if err := admit.KnownKeys(record, []string{"expectedDesiredStateId", "expectedTransactionId", "failureClass", "nonClaims", "operation", "receiptId", "receiptKind", "schemaVersion", "state", "transactionResult"}, "adoption materialization receipt"); err != nil {
		return Receipt{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["receiptKind"] != ReceiptKind {
		return Receipt{}, fmt.Errorf("adoption materialization receipt identity is invalid")
	}
	operation, err := admit.Enum(record["operation"], map[string]struct{}{OperationApply: {}, OperationRecover: {}}, "adoption materialization receipt operation")
	if err != nil {
		return Receipt{}, err
	}
	state, err := admit.Enum(record["state"], receiptStateSet, "adoption materialization receipt state")
	if err != nil {
		return Receipt{}, err
	}
	receiptID, err := admit.SHA256Ref(record["receiptId"], "adoption materialization receipt receiptId")
	if err != nil {
		return Receipt{}, err
	}
	expectedTransactionID, err := nullableSHA256Ref(record["expectedTransactionId"], "adoption materialization receipt expectedTransactionId")
	if err != nil {
		return Receipt{}, err
	}
	expectedDesiredStateID, err := nullableSHA256Ref(record["expectedDesiredStateId"], "adoption materialization receipt expectedDesiredStateId")
	if err != nil {
		return Receipt{}, err
	}
	failureClass := ""
	if record["failureClass"] != nil {
		failureClass, err = admit.NonEmptyText(record["failureClass"], "adoption materialization receipt failureClass")
		if err != nil {
			return Receipt{}, err
		}
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "adoption materialization receipt nonClaims", false)
	if err != nil || !containsEvery(nonClaims, boundaryNonClaims) {
		return Receipt{}, fmt.Errorf("adoption materialization receipt nonClaims are invalid")
	}
	var transactionResult *repositorytransaction.Result
	if record["transactionResult"] != nil {
		result, err := repositorytransaction.AdmitResultOutput(record["transactionResult"])
		if err != nil {
			return Receipt{}, err
		}
		transactionResult = &result
	}
	receipt := Receipt{
		ExpectedDesiredStateID: expectedDesiredStateID, ExpectedTransactionID: expectedTransactionID,
		FailureClass: failureClass, NonClaims: nonClaims, Operation: operation, ReceiptID: receiptID,
		State: state, TransactionResult: transactionResult,
	}
	if err := validateReceiptRelation(receipt); err != nil {
		return Receipt{}, err
	}
	wantID, err := digest.StableJSONSHA256Ref(receipt.identityValue())
	if err != nil || wantID != receiptID {
		return Receipt{}, fmt.Errorf("adoption materialization receipt identity does not match its content")
	}
	actual, err := stablejson.Marshal(record)
	if err != nil {
		return Receipt{}, fmt.Errorf("encode adoption materialization receipt")
	}
	expected, err := stablejson.Marshal(receipt.JSONValue())
	if err != nil || !bytes.Equal(actual, expected) || len(actual) > MaximumOutputBytes {
		return Receipt{}, fmt.Errorf("adoption materialization receipt is not canonical")
	}
	return receipt, nil
}

func validatePlanRouteClosure(manifest Manifest, transaction repositorytransaction.Plan) error {
	wantPaths := make([]string, 0, len(manifest.Routes)+1)
	wantPaths = append(wantPaths, ProjectManifestPath)
	for _, route := range manifest.Routes {
		wantPaths = append(wantPaths, route.Path)
	}
	slices.Sort(wantPaths)
	gotPaths := make([]string, 0, len(transaction.Operations))
	for _, operation := range transaction.Operations {
		if !operation.After.Exists || operation.After.Mode != 0o644 {
			return fmt.Errorf("adoption materialization transaction target projection is invalid")
		}
		gotPaths = append(gotPaths, operation.Path)
		if operation.Path == ProjectManifestPath {
			content, err := stablejson.Marshal(manifest.JSONValue())
			if err != nil || operation.After.ByteCount != int64(len(content)) || operation.After.SHA256 != digest.SHA256BytesRef(content) {
				return fmt.Errorf("adoption materialization manifest transaction target is inconsistent")
			}
		}
	}
	if !slices.Equal(gotPaths, wantPaths) {
		return fmt.Errorf("adoption materialization manifest routes do not close the transaction target set")
	}
	return nil
}

func validateReceiptRelation(receipt Receipt) error {
	if receipt.ExpectedTransactionID == "" {
		return fmt.Errorf("adoption materialization receipt requires an expected transaction identity")
	}
	if receipt.Operation == OperationApply && receipt.ExpectedDesiredStateID == "" {
		return fmt.Errorf("adoption materialization apply receipt requires an expected desired-state identity")
	}
	if receipt.Operation == OperationRecover && receipt.ExpectedDesiredStateID != "" {
		return fmt.Errorf("adoption materialization recovery receipt must not claim an expected desired state")
	}
	if receipt.TransactionResult == nil {
		if receipt.State != ReceiptStateBlocked || receipt.FailureClass == "" {
			return fmt.Errorf("adoption materialization receipt without transaction result must be blocked")
		}
		return nil
	}
	wantState, _ := receiptOutcome(receipt.Operation, *receipt.TransactionResult)
	if receipt.State != wantState || receipt.FailureClass != receipt.TransactionResult.FailureClass {
		return fmt.Errorf("adoption materialization receipt outcome contradicts its transaction result")
	}
	if receipt.State == ReceiptStatePassed && receipt.TransactionResult.TransactionID != "" && receipt.TransactionResult.TransactionID != receipt.ExpectedTransactionID {
		return fmt.Errorf("adoption materialization passed receipt transaction identity is inconsistent")
	}
	return nil
}

func nullableSHA256Ref(raw any, context string) (string, error) {
	if raw == nil {
		return "", nil
	}
	return admit.SHA256Ref(raw, context)
}

func containsEvery(values, required []string) bool {
	for _, candidate := range required {
		if !slices.Contains(values, candidate) {
			return false
		}
	}
	return true
}
