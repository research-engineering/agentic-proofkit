package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"os"
)

type failurePoint string

const (
	faultAfterJournal      failurePoint = "after_journal"
	faultAfterStaging      failurePoint = "after_staging"
	faultAfterReady        failurePoint = "after_ready"
	faultAfterDirectory    failurePoint = "after_directory"
	faultBeforePublish     failurePoint = "before_publish"
	faultAfterPublish      failurePoint = "after_publish"
	faultAfterRollback     failurePoint = "after_rollback"
	faultAfterTerminal     failurePoint = "after_terminal"
	faultAfterStateRemoval failurePoint = "after_state_removal"
	faultBeforeCleanup     failurePoint = "before_cleanup"
)

type engine struct {
	fault func(failurePoint, int) error
}

type transactionLock struct {
	directory *os.File
}

func Apply(ctx context.Context, rootPath string, plan Plan) (Result, error) {
	return engine{}.apply(ctx, rootPath, plan)
}

func Recover(ctx context.Context, rootPath, transactionID, action string) (Result, error) {
	return engine{}.recover(ctx, rootPath, transactionID, action)
}

func (runtime engine) apply(ctx context.Context, rootPath string, plan Plan) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction apply cancelled: %w", err)
	}
	plan = clonePlan(plan)
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	if err := validateExecutablePlan(plan, rootID); err != nil {
		return Result{}, err
	}
	changed := changedCount(plan)
	prefix, err := classifyPrefix(root, plan)
	if err != nil {
		return Result{}, fmt.Errorf("repository transaction target snapshot changed")
	}
	if prefix != 0 && prefix != changed {
		return Result{}, fmt.Errorf("repository transaction target snapshot is a partial prefix without recovery state")
	}
	if prefix != changed {
		if err := verifyCreatedDirectories(root, plan); err != nil {
			return Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction apply cancelled: %w", err)
	}
	lock, err := acquireTransactionLock(root)
	if err != nil {
		return Result{}, err
	}
	defer lock.release()
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction apply cancelled: %w", err)
	}
	if pending, err := pendingTransactionState(root); err != nil {
		return Result{}, err
	} else if pending.Exists {
		return Result{}, &RecoveryRequiredError{TransactionID: pending.TransactionID}
	}
	prefix, err = classifyPrefix(root, plan)
	if err != nil {
		return Result{}, fmt.Errorf("repository transaction target snapshot changed")
	}
	if prefix == changed {
		return Result{AppliedCountKnown: true, State: StateAlreadySatisfied, TransactionID: plan.TransactionID}, nil
	}
	if prefix != 0 {
		return Result{}, fmt.Errorf("repository transaction target snapshot is a partial prefix without recovery state")
	}
	if err := verifyCreatedDirectories(root, plan); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction apply cancelled: %w", err)
	}
	if err := prepareJournal(root, plan); err != nil {
		return runtime.abortPreparingFailure(root, plan)
	}
	if err := ctx.Err(); err != nil {
		return runtime.finishPreparingFailure(root, plan, "cancelled")
	}
	if err := runtime.callFault(faultAfterJournal, -1); err != nil {
		return runtime.finishPreparingFailure(root, plan, "injected_prepare_failure")
	}
	if err := stageObjects(root, plan); err != nil {
		return runtime.finishPreparingFailure(root, plan, "object_staging_failed")
	}
	if err := ctx.Err(); err != nil {
		return runtime.finishPreparingFailure(root, plan, "cancelled")
	}
	if err := runtime.callFault(faultAfterStaging, -1); err != nil {
		return runtime.finishPreparingFailure(root, plan, "injected_prepare_failure")
	}
	if err := verifyTargetVector(root, plan, 0); err != nil {
		return runtime.finishPreparingFailure(root, plan, "target_changed_before_ready")
	}
	if err := writeMarker(root, readyMarker); err != nil {
		return runtime.finishPreparingFailure(root, plan, "ready_marker_failed")
	}
	if err := discardTerminalReceipt(root); err != nil {
		return Result{FailureClass: "terminal_replacement_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := runtime.callFault(faultAfterReady, -1); err != nil {
		return runtime.rollbackAfterFailure(context.WithoutCancel(ctx), root, plan, "injected_apply_failure")
	}
	if err := runtime.applyForward(ctx, root, plan, 0); err != nil {
		failureClass := "publication_failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			failureClass = "cancelled"
		}
		return runtime.rollbackAfterFailure(context.WithoutCancel(ctx), root, plan, failureClass)
	}
	if err := writeMarker(root, committedMarker); err != nil {
		return Result{AppliedCount: changed, AppliedCountKnown: true, FailureClass: "terminal_marker_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := runtime.callFault(faultAfterTerminal, -1); err != nil {
		return Result{AppliedCount: changed, AppliedCountKnown: true, FailureClass: "injected_cleanup_failure", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := runtime.callFault(faultBeforeCleanup, -1); err != nil {
		return Result{AppliedCount: changed, AppliedCountKnown: true, FailureClass: "injected_cleanup_failure", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	terminal := Result{AppliedCount: changed, AppliedCountKnown: true, State: StateApplied, TransactionID: plan.TransactionID}
	if err := runtime.archiveAndCleanupTerminal(root, plan, terminal); err != nil {
		if errors.Is(err, errCleanupDurabilityUnknown) {
			return Result{AppliedCount: changed, AppliedCountKnown: true, FailureClass: "applied_cleanup_durability_unknown", State: StateDurabilityUnknown, TransactionID: plan.TransactionID}, nil
		}
		return Result{AppliedCount: changed, AppliedCountKnown: true, FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	return terminal, nil
}

func (runtime engine) callFault(point failurePoint, index int) error {
	if runtime.fault == nil {
		return nil
	}
	return runtime.fault(point, index)
}
