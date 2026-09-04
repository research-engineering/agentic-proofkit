package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func (runtime engine) recover(ctx context.Context, rootPath, transactionID, action string) (Result, error) {
	if action != RecoveryResume && action != RecoveryRollback {
		return Result{}, fmt.Errorf("repository transaction recovery action must be resume or rollback")
	}
	admittedTransactionID, err := admit.SHA256Ref(transactionID, "repository transaction recovery transactionId")
	if err != nil {
		return Result{}, err
	}
	transactionID = admittedTransactionID
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
	}
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	lock, exists, err := acquireExistingTransactionLock(root)
	if err != nil {
		return Result{}, err
	}
	if !exists {
		return Result{}, fmt.Errorf("repository transaction recovery state is absent")
	}
	defer lock.release()
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
	}
	entries, err := controlEntries(root)
	if err != nil {
		return Result{}, err
	}
	active := false
	for _, entry := range entries {
		if entry.Name() == "active" && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			active = true
		}
	}
	if !active {
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if result, handled, err := runtime.recoverTerminalTombstone(root, entries, transactionID, action); handled || err != nil {
			return result, err
		}
		if len(entries) > 0 {
			return Result{FailureClass: "conflicting_control_state", State: StateRecoveryRequired}, nil
		}
		return Result{}, fmt.Errorf("repository transaction recovery state is absent")
	}
	if len(entries) != 1 {
		return Result{FailureClass: "conflicting_control_state", State: StateRecoveryRequired}, nil
	}
	if err := validatePrivateDirectory(root, activeDirectory, 0o700); err != nil {
		return Result{FailureClass: "invalid_control_state", State: StateRecoveryRequired}, nil
	}
	plan, err := loadJournal(root)
	if err != nil {
		observedTransactionID, identityKnown, discardable, inspectErr := incompleteJournalCanBeDiscarded(root)
		if inspectErr != nil || !discardable {
			return Result{FailureClass: "invalid_journal", State: StateRecoveryRequired, TransactionID: observedTransactionID}, nil
		}
		if identityKnown && observedTransactionID != transactionID {
			return Result{}, fmt.Errorf("repository transaction recovery identity does not match preparing state")
		}
		if action != RecoveryRollback {
			return Result{FailureClass: "preparing_state_mismatch", State: StateRecoveryRequired, TransactionID: observedTransactionID}, nil
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if cleanupErr := cleanupActive(root, nil); cleanupErr != nil {
			if errors.Is(cleanupErr, errCleanupDurabilityUnknown) {
				return Result{AppliedCountKnown: true, FailureClass: "preparing_cleanup_durability_unknown", RecoveredBy: RecoveryRollback, State: StateDurabilityUnknown}, nil
			}
			return Result{FailureClass: "cleanup_failed", RecoveredBy: RecoveryRollback, State: StateCleanupRequired, TransactionID: observedTransactionID}, nil
		}
		return Result{AppliedCountKnown: true, RecoveredBy: RecoveryRollback, State: StateRolledBack, TransactionID: observedTransactionID}, nil
	}
	if plan.TransactionID != transactionID || plan.RootID != rootID {
		return Result{}, fmt.Errorf("repository transaction recovery identity does not match active state")
	}
	if err := validateActiveState(root, plan); err != nil {
		return Result{FailureClass: "invalid_control_state", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	committed, err := markerExists(root, committedMarker)
	if err != nil {
		return Result{}, err
	}
	rolledBack, err := markerExists(root, rolledBackMarker)
	if err != nil {
		return Result{}, err
	}
	if committed && rolledBack {
		return Result{FailureClass: "conflicting_terminal_markers", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	if committed {
		plan, err = loadObjects(root, plan)
		if err != nil {
			return Result{FailureClass: "invalid_staged_objects", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if action != RecoveryResume || verifyTargetVector(root, plan, changedCount(plan)) != nil {
			return Result{FailureClass: "committed_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		return runtime.cleanupRecovered(root, plan, StateApplied, action)
	}
	if rolledBack {
		plan, err = loadObjects(root, plan)
		if err != nil {
			return Result{FailureClass: "invalid_staged_objects", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if action != RecoveryRollback || verifyTargetVector(root, plan, 0) != nil {
			return Result{FailureClass: "rolled_back_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if removeCreatedDirectories(root, plan) != nil {
			return Result{FailureClass: "rolled_back_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		return runtime.cleanupRecovered(root, plan, StateRolledBack, RecoveryRollback)
	}
	ready, err := markerExists(root, readyMarker)
	if err != nil {
		return Result{}, err
	}
	if !ready {
		if action != RecoveryRollback {
			return Result{FailureClass: "preparing_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if verifyTargetVector(root, plan, 0) != nil {
			return Result{FailureClass: "preparing_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if err := removeCreatedDirectories(root, plan); err != nil {
			return Result{FailureClass: "directory_cleanup_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := cleanupActive(root, &plan); err != nil {
			if errors.Is(err, errCleanupDurabilityUnknown) {
				return Result{AppliedCountKnown: true, FailureClass: "rolled_back_cleanup_durability_unknown", RecoveredBy: RecoveryRollback, State: StateDurabilityUnknown, TransactionID: transactionID}, nil
			}
			return Result{AppliedCountKnown: true, FailureClass: "cleanup_failed", RecoveredBy: RecoveryRollback, State: StateCleanupRequired, TransactionID: transactionID}, nil
		}
		return Result{AppliedCountKnown: true, RecoveredBy: RecoveryRollback, State: StateRolledBack, TransactionID: transactionID}, nil
	}
	plan, err = loadObjects(root, plan)
	if err != nil {
		return Result{FailureClass: "invalid_staged_objects", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	prefix, err := classifyPrefix(root, plan)
	if err != nil {
		return Result{FailureClass: "ambiguous_target_state", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	if action == RecoveryResume {
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if err := runtime.applyForward(context.WithoutCancel(ctx), root, plan, prefix); err != nil {
			return resultWithObservedPrefix(root, plan, Result{FailureClass: "resume_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: transactionID}), nil
		}
		if err := writeMarker(root, committedMarker); err != nil {
			return Result{AppliedCount: changedCount(plan), AppliedCountKnown: true, FailureClass: "terminal_marker_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		return runtime.cleanupRecovered(root, plan, StateApplied, action)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
	}
	if err := runtime.rollbackPrefix(context.WithoutCancel(ctx), root, plan, prefix); err != nil {
		return resultWithObservedPrefix(root, plan, Result{FailureClass: "rollback_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: transactionID}), nil
	}
	if err := removeInterruptedTemporary(root, plan); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "temporary_cleanup_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	if err := removeCreatedDirectories(root, plan); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "directory_cleanup_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	if err := writeMarker(root, rolledBackMarker); err != nil {
		return Result{AppliedCountKnown: true, FailureClass: "terminal_marker_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	return runtime.cleanupRecovered(root, plan, StateRolledBack, action)
}

func (runtime engine) cleanupRecovered(root *os.Root, plan Plan, state, action string) (Result, error) {
	if err := removeInterruptedTemporary(root, plan); err != nil {
		return Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, FailureClass: "temporary_cleanup_failed", RecoveredBy: action, State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	}
	if err := runtime.archiveAndCleanupTerminal(root, plan, state); err != nil {
		if errors.Is(err, errCleanupDurabilityUnknown) {
			return Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, FailureClass: state + "_cleanup_durability_unknown", RecoveredBy: action, State: StateDurabilityUnknown, TransactionID: plan.TransactionID}, nil
		}
		return Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, FailureClass: "cleanup_failed", RecoveredBy: action, State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	return Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, RecoveredBy: action, State: state, TransactionID: plan.TransactionID}, nil
}

func (runtime engine) recoverTerminalTombstone(root *os.Root, entries []fs.DirEntry, transactionID, action string) (Result, bool, error) {
	if len(entries) != 1 {
		return Result{}, false, nil
	}
	entry := entries[0]
	if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
		return Result{}, false, nil
	}
	appliedPath := terminalTombstonePath(transactionID, StateApplied)
	rolledBackPath := terminalTombstonePath(transactionID, StateRolledBack)
	path := ControlDirectory + "/" + entry.Name()
	state := ""
	switch path {
	case appliedPath:
		if action != RecoveryResume {
			return Result{FailureClass: "committed_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, true, nil
		}
		state = StateApplied
	case rolledBackPath:
		if action != RecoveryRollback {
			return Result{FailureClass: "rolled_back_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, true, nil
		}
		state = StateRolledBack
	default:
		return Result{}, false, nil
	}
	receipt, err := loadTerminalReceipt(root, path)
	if err != nil || receipt.TransactionID != transactionID || receipt.State != state {
		return Result{FailureClass: "invalid_terminal_receipt", State: StateRecoveryRequired, TransactionID: transactionID}, true, nil
	}
	if err := runtime.cleanupTerminalTombstone(root, path); err != nil {
		if errors.Is(err, errCleanupDurabilityUnknown) {
			return Result{FailureClass: state + "_cleanup_durability_unknown", RecoveredBy: action, State: StateDurabilityUnknown, TransactionID: transactionID}, true, nil
		}
		return Result{FailureClass: "cleanup_failed", RecoveredBy: action, State: StateCleanupRequired, TransactionID: transactionID}, true, nil
	}
	return Result{AppliedCount: receipt.AppliedCount, AppliedCountKnown: true, RecoveredBy: action, State: state, TransactionID: transactionID}, true, nil
}
