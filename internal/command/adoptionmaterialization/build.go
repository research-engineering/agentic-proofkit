package adoptionmaterialization

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func BuildPlan(ctx context.Context, raw any, repositoryRoot string) (Plan, error) {
	request, err := admitRequest(raw)
	if err != nil {
		return Plan{}, err
	}
	children, err := childArtifacts(request)
	if err != nil {
		return Plan{}, err
	}
	manifest, err := buildManifest(request, children)
	if err != nil {
		return Plan{}, err
	}
	manifestArtifact, err := encodeArtifact(ArtifactProjectManifest, manifest.ManifestID, ProjectManifestPath, manifest.JSONValue())
	if err != nil {
		return Plan{}, err
	}
	artifacts := append(children, manifestArtifact)
	targets := make([]repositorytransaction.Target, 0, len(artifacts))
	for _, item := range artifacts {
		targets = append(targets, repositorytransaction.Target{Content: item.Content, Mode: 0o644, Path: item.Path})
	}
	transaction, err := repositorytransaction.BuildPlan(ctx, repositoryRoot, targets)
	if err != nil {
		return Plan{}, err
	}
	if err := validateExistingArtifacts(transaction, artifacts, request.ProjectID); err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Manifest: manifest, NonClaims: mergedNonClaims(request.NonClaims), ProjectID: request.ProjectID,
		RequestID: request.RequestID, SourceIntent: request.SourceIntent, SourcePlanID: request.SourcePlanID,
		Transaction: transaction,
	}
	if _, err := AdmitPlanOutput(plan.JSONValue()); err != nil {
		return Plan{}, fmt.Errorf("admit adoption materialization plan output: %w", err)
	}
	encoded, err := stablejson.Marshal(plan.JSONValue())
	if err != nil || len(encoded) > MaximumOutputBytes {
		return Plan{}, fmt.Errorf("adoption materialization plan exceeds its output byte limit")
	}
	return plan, nil
}

func Apply(ctx context.Context, raw any, repositoryRoot, expectedTransactionID, expectedDesiredStateID string) (Receipt, int, error) {
	expected, err := admit.SHA256Ref(expectedTransactionID, "adoption materialization expected transaction")
	if err != nil {
		return Receipt{}, 1, err
	}
	expectedDesired, err := admit.SHA256Ref(expectedDesiredStateID, "adoption materialization expected desired state")
	if err != nil {
		return Receipt{}, 1, err
	}
	plan, err := BuildPlan(ctx, raw, repositoryRoot)
	if err != nil {
		if errors.Is(err, repositorytransaction.ErrRecoveryRequired) {
			return pendingReceipt(OperationApply, expected, expectedDesired, err, nil)
		}
		return Receipt{}, 1, err
	}
	if plan.Transaction.DesiredStateID != expectedDesired {
		return blockedReceipt(OperationApply, expected, expectedDesired, "desired_state_identity_mismatch", plan.NonClaims)
	}
	if plan.Transaction.TransactionID != expected {
		if transactionHasChanges(plan.Transaction) {
			return blockedReceipt(OperationApply, expected, expectedDesired, "transaction_identity_mismatch", plan.NonClaims)
		}
		terminal, terminalErr := repositorytransaction.ReadTerminalResult(ctx, repositoryRoot, expected)
		replay, failureClass, replayErr := classifyTerminalReplay(terminal, terminalErr)
		if replayErr != nil {
			return Receipt{}, 1, replayErr
		}
		if failureClass != "" {
			return blockedReceipt(OperationApply, expected, expectedDesired, failureClass, plan.NonClaims)
		}
		return resultReceipt(OperationApply, expected, expectedDesired, replay, plan.NonClaims)
	}
	result, err := repositorytransaction.Apply(ctx, repositoryRoot, plan.Transaction)
	if err != nil {
		if errors.Is(err, repositorytransaction.ErrBusy) || errors.Is(err, repositorytransaction.ErrRecoveryRequired) {
			if errors.Is(err, repositorytransaction.ErrRecoveryRequired) {
				return pendingReceipt(OperationApply, expected, expectedDesired, err, plan.NonClaims)
			}
			return blockedReceipt(OperationApply, expected, expectedDesired, "transaction_busy", plan.NonClaims)
		}
		return Receipt{}, 1, err
	}
	return resultReceipt(OperationApply, expected, expectedDesired, result, plan.NonClaims)
}

func classifyTerminalReplay(result repositorytransaction.Result, err error) (repositorytransaction.Result, string, error) {
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return repositorytransaction.Result{}, "", err
		case errors.Is(err, repositorytransaction.ErrBusy):
			return repositorytransaction.Result{}, "transaction_busy", nil
		default:
			return repositorytransaction.Result{}, "transaction_identity_mismatch", nil
		}
	}
	if result.State != repositorytransaction.StateApplied {
		return repositorytransaction.Result{}, "transaction_identity_mismatch", nil
	}
	result.AppliedCount = 0
	result.AppliedCountKnown = true
	result.RecoveredBy = ""
	result.State = repositorytransaction.StateAlreadySatisfied
	return result, "", nil
}

func Recover(ctx context.Context, repositoryRoot, transactionID, action string) (Receipt, int, error) {
	admittedID, err := admit.SHA256Ref(transactionID, "adoption materialization transaction")
	if err != nil {
		return Receipt{}, 1, err
	}
	result, err := repositorytransaction.Recover(ctx, repositoryRoot, admittedID, action)
	if err != nil {
		return Receipt{}, 1, err
	}
	return resultReceipt(OperationRecover, admittedID, "", result, nil)
}

func resultReceipt(operation, expectedTransactionID, expectedDesiredStateID string, result repositorytransaction.Result, nonClaims []string) (Receipt, int, error) {
	state, exitCode := receiptOutcome(operation, result)
	receipt, err := newReceipt(operation, state, result.FailureClass, expectedTransactionID, expectedDesiredStateID, &result, nonClaims)
	if err != nil {
		return Receipt{}, 1, err
	}
	return receipt, exitCode, nil
}

func transactionHasChanges(plan repositorytransaction.Plan) bool {
	for _, operation := range plan.Operations {
		if operation.Action != repositorytransaction.ActionUnchanged {
			return true
		}
	}
	return false
}

func blockedReceipt(operation, expectedTransactionID, expectedDesiredStateID, failureClass string, nonClaims []string) (Receipt, int, error) {
	receipt, err := newReceipt(operation, ReceiptStateBlocked, failureClass, expectedTransactionID, expectedDesiredStateID, nil, nonClaims)
	return receipt, 1, err
}

func pendingReceipt(operation, expectedTransactionID, expectedDesiredStateID string, cause error, nonClaims []string) (Receipt, int, error) {
	transactionID, _ := repositorytransaction.RecoveryTransactionID(cause)
	result := repositorytransaction.Result{
		FailureClass:  "pending_transaction_state",
		State:         repositorytransaction.StateRecoveryRequired,
		TransactionID: transactionID,
	}
	return resultReceipt(operation, expectedTransactionID, expectedDesiredStateID, result, nonClaims)
}

func receiptOutcome(operation string, result repositorytransaction.Result) (string, int) {
	if operation == OperationApply && (result.State == repositorytransaction.StateApplied || result.State == repositorytransaction.StateAlreadySatisfied) {
		return ReceiptStatePassed, 0
	}
	if operation == OperationRecover && (result.State == repositorytransaction.StateApplied || result.State == repositorytransaction.StateRolledBack) {
		return ReceiptStatePassed, 0
	}
	switch result.State {
	case repositorytransaction.StateCleanupRequired:
		return ReceiptStateCleanupRequired, 1
	case repositorytransaction.StateDurabilityUnknown:
		return ReceiptStateDurabilityUnknown, 1
	case repositorytransaction.StateRecoveryRequired:
		return ReceiptStateRecoveryRequired, 1
	default:
		return ReceiptStateFailed, 1
	}
}

func childArtifacts(request Request) ([]artifact, error) {
	items := make([]artifact, 0, len(request.Sources)+2)
	for _, source := range request.Sources {
		item, err := encodeArtifact(ArtifactRequirementSource, source.SourceID, source.RequirementsPath, requirementsourceadmission.SourceValue(source))
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	binding, err := encodeArtifact(ArtifactRequirementBinding, request.Binding.BindingID, request.BindingPath, requirementbinding.InputValue(request.Binding))
	if err != nil {
		return nil, err
	}
	items = append(items, binding)
	inventory, err := encodeArtifact(ArtifactTestInventory, request.Inventory.InventoryID, request.InventoryPath, testevidenceinventory.InventoryValue(request.Inventory))
	if err != nil {
		return nil, err
	}
	items = append(items, inventory)
	return items, nil
}

func encodeArtifact(kind, id, path string, value map[string]any) (artifact, error) {
	content, err := stablejson.Marshal(value)
	if err != nil {
		return artifact{}, fmt.Errorf("encode adoption materialization artifact")
	}
	if len(content) > repositorytransaction.MaximumFileBytes {
		return artifact{}, fmt.Errorf("adoption materialization artifact exceeds its file byte limit")
	}
	return artifact{Content: content, ID: id, Kind: kind, Path: path}, nil
}

func validateExistingArtifacts(transaction repositorytransaction.Plan, artifacts []artifact, projectID string) error {
	byPath := map[string]artifact{}
	for _, item := range artifacts {
		byPath[item.Path] = item
	}
	for index, operation := range transaction.Operations {
		if !operation.Before.Exists {
			continue
		}
		content, ok := transaction.BeforeContent(index)
		if !ok {
			return fmt.Errorf("adoption materialization existing artifact bytes are unavailable")
		}
		item, ok := byPath[operation.Path]
		if !ok {
			return fmt.Errorf("adoption materialization transaction contains an undeclared artifact")
		}
		if err := admitExistingArtifact(content, item, projectID); err != nil {
			return err
		}
	}
	return nil
}

func admitExistingArtifact(content []byte, desired artifact, projectID string) error {
	if desired.Kind != ArtifactProjectManifest {
		identity, admitted := admitProjectChildRecord(content, Route{ArtifactKind: desired.Kind, Path: desired.Path}, &admittedProjectChildren{})
		if !admitted || identity != desired.ID {
			return fmt.Errorf("adoption materialization existing artifact has incompatible ownership")
		}
		return nil
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), repositorytransaction.MaximumFileBytes)
	if err != nil {
		return fmt.Errorf("adoption materialization refuses to replace an unknown existing artifact")
	}
	switch desired.Kind {
	case ArtifactProjectManifest:
		manifest, err := AdmitManifest(raw)
		if err != nil || manifest.ProjectID != projectID {
			return fmt.Errorf("adoption materialization existing project manifest has incompatible ownership")
		}
	default:
		return fmt.Errorf("adoption materialization artifact kind is unsupported")
	}
	return nil
}
