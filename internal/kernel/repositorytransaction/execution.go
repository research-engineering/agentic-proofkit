package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func (runtime engine) applyForward(ctx context.Context, root *os.Root, plan Plan, prefix int) error {
	if err := ensureTargetDirectories(root, plan); err != nil {
		return err
	}
	for directoryIndex := range plan.CreatedDirectories {
		if err := runtime.callFault(faultAfterDirectory, directoryIndex); err != nil {
			return err
		}
	}
	changedIndex := 0
	for operationIndex, operation := range plan.Operations {
		if operation.Action == ActionUnchanged {
			continue
		}
		if changedIndex < prefix {
			changedIndex++
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("repository transaction operation cancelled: %w", err)
		}
		if err := runtime.callFault(faultBeforePublish, changedIndex); err != nil {
			return err
		}
		if err := publishContent(root, plan, operationIndex, operation.Before, operation.afterContent, operation.After.Mode); err != nil {
			return err
		}
		changedIndex++
		if err := runtime.callFault(faultAfterPublish, changedIndex); err != nil {
			return err
		}
	}
	return nil
}

func (runtime engine) rollbackAfterFailure(ctx context.Context, root *os.Root, plan Plan, failureClass string) (Result, error) {
	prefix, err := classifyPrefix(root, plan)
	if err != nil {
		return Result{FailureClass: failureClass, State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := selectRecoveryAction(root, plan.TransactionID, RecoveryRollback); err != nil {
		return Result{FailureClass: "recovery_action_persistence_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := runtime.rollbackPrefix(ctx, root, plan, prefix); err != nil {
		return resultWithObservedPrefix(root, plan, Result{FailureClass: "rollback_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}), nil
	}
	if err := removeInterruptedTemporary(root, plan); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "temporary_cleanup_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := removeCreatedDirectories(root, plan); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "directory_cleanup_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := writeMarker(root, rolledBackMarker); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "terminal_marker_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	terminal := Result{AppliedCountKnown: true, FailureClass: failureClass, State: StateRolledBack, TransactionID: plan.TransactionID}
	if err := runtime.archiveAndCleanupTerminal(root, plan, terminal); err != nil {
		if errors.Is(err, errCleanupDurabilityUnknown) {
			return Result{AppliedCountKnown: true, FailureClass: "rolled_back_cleanup_durability_unknown", State: StateDurabilityUnknown, TransactionID: plan.TransactionID}, nil
		}
		return Result{AppliedCountKnown: true, FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	return terminal, nil
}

func (runtime engine) rollbackPrefix(ctx context.Context, root *os.Root, plan Plan, prefix int) error {
	changed := changedOperationIndexes(plan)
	restored := 0
	for position := prefix - 1; position >= 0; position-- {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("repository transaction rollback cancelled: %w", err)
		}
		operationIndex := changed[position]
		operation := plan.Operations[operationIndex]
		if operation.Action == ActionCreate {
			if err := removeCreatedTarget(root, operation); err != nil {
				return err
			}
		} else if err := publishContent(root, plan, operationIndex, operation.After, operation.beforeContent, operation.Before.Mode); err != nil {
			return err
		}
		restored++
		if err := runtime.callFault(faultAfterRollback, restored); err != nil {
			return err
		}
	}
	return nil
}

func (runtime engine) finishPreparingFailure(root *os.Root, plan Plan, failureClass string) (Result, error) {
	exists, err := pathExists(root, activeDirectory)
	if err != nil {
		return Result{FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	if !exists {
		return Result{}, fmt.Errorf("repository transaction preparing state is absent")
	}
	if err := verifyTargetVector(root, plan, 0); err != nil {
		return Result{FailureClass: "preparing_state_mismatch", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := selectRecoveryAction(root, plan.TransactionID, RecoveryRollback); err != nil {
		return Result{FailureClass: "recovery_action_persistence_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := writeMarker(root, rolledBackMarker); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "terminal_marker_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := discardTerminalReceipt(root); err != nil {
		return Result{FailureClass: "terminal_replacement_failed", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	terminal := Result{AppliedCountKnown: true, FailureClass: failureClass, State: StateRolledBack, TransactionID: plan.TransactionID}
	if err := runtime.archiveAndCleanupTerminal(root, plan, terminal); err != nil {
		if errors.Is(err, errCleanupDurabilityUnknown) {
			return Result{AppliedCountKnown: true, FailureClass: "preparing_cleanup_durability_unknown", State: StateDurabilityUnknown, TransactionID: plan.TransactionID}, nil
		}
		return Result{AppliedCountKnown: true, FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	return terminal, nil
}

func (runtime engine) abortPreparingFailure(root *os.Root, plan Plan) (Result, error) {
	exists, err := pathExists(root, activeDirectory)
	if err != nil {
		return Result{FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	if exists {
		if err := cleanupActive(root, &plan); err != nil {
			if errors.Is(err, errCleanupDurabilityUnknown) {
				return Result{FailureClass: "preparing_cleanup_durability_unknown", State: StateDurabilityUnknown, TransactionID: plan.TransactionID}, nil
			}
			return Result{FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
		}
	}
	return Result{}, fmt.Errorf("repository transaction journal preparation failed")
}

func removeInterruptedTemporary(root *os.Root, plan Plan) error {
	for index, operation := range plan.Operations {
		if operation.Action == ActionUnchanged {
			continue
		}
		temporary := transactionTemporaryPath(plan.TransactionID, index, operation.Path)
		info, err := root.Lstat(filepath.FromSlash(temporary))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("repository transaction temporary route is unsafe")
		}
		owned, ownershipErr := platformOwnedByCurrentUser(info)
		if ownershipErr != nil || !owned {
			return fmt.Errorf("repository transaction temporary route is not owned")
		}
		if err := root.Remove(filepath.FromSlash(temporary)); err != nil {
			return fmt.Errorf("remove repository transaction temporary file")
		}
	}
	return nil
}
