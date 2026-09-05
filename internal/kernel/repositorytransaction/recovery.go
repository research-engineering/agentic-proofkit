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
	if len(entries) > 2 {
		return Result{FailureClass: "conflicting_control_state", State: StateRecoveryRequired}, nil
	}
	if _, _, err := findTerminalControlEntry(entries); err != nil {
		return Result{FailureClass: "conflicting_control_state", State: StateRecoveryRequired}, nil
	}
	if err := validatePrivateDirectory(root, activeDirectory, 0o700); err != nil {
		return Result{FailureClass: "invalid_control_state", State: StateRecoveryRequired}, nil
	}
	plan, err := loadJournal(root)
	if err != nil {
		preparingPlan, identityKnown, inspectErr := loadPreparingJournal(root)
		if inspectErr != nil || !identityKnown {
			return Result{FailureClass: "invalid_journal", State: StateRecoveryRequired}, nil
		}
		if preparingPlan.TransactionID != transactionID || preparingPlan.RootID != rootID {
			return Result{}, fmt.Errorf("repository transaction recovery identity does not match preparing state")
		}
		if err := validateActivePlan(preparingPlan); err != nil {
			return Result{FailureClass: "invalid_control_state", State: StateRecoveryRequired, TransactionID: preparingPlan.TransactionID}, nil
		}
		if action != RecoveryRollback {
			return Result{FailureClass: "preparing_state_mismatch", State: StateRecoveryRequired, TransactionID: preparingPlan.TransactionID}, nil
		}
		if err := verifyTargetVector(root, preparingPlan, 0); err != nil {
			return recoveryObservationFailure(preparingPlan.TransactionID, "preparing_state_mismatch", err)
		}
		if err := publishPreparingJournal(root); err != nil {
			return Result{FailureClass: "journal_publication_failed", State: StateRecoveryRequired, TransactionID: preparingPlan.TransactionID}, nil
		}
		plan = preparingPlan
	}
	if plan.TransactionID != transactionID || plan.RootID != rootID {
		return Result{}, fmt.Errorf("repository transaction recovery identity does not match active state")
	}
	if err := validateActiveState(root, plan); err != nil {
		return Result{FailureClass: "invalid_control_state", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	selectedAction, actionSelected, err := readRecoveryAction(root)
	if err != nil {
		return Result{FailureClass: "invalid_recovery_action", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	if actionSelected && (selectedAction.TransactionID != transactionID || selectedAction.Action != action) {
		return Result{FailureClass: "recovery_action_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
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
		if action != RecoveryResume {
			return Result{FailureClass: "committed_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := verifyTargetVector(root, plan, changedCount(plan)); err != nil {
			return recoveryObservationFailure(transactionID, "committed_state_mismatch", err)
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if err := discardTerminalReceipt(root); err != nil {
			return Result{FailureClass: "terminal_replacement_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		return runtime.cleanupRecovered(root, plan, StateApplied, action)
	}
	if rolledBack {
		if action != RecoveryRollback {
			return Result{FailureClass: "rolled_back_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := verifyTargetVector(root, plan, 0); err != nil {
			return recoveryObservationFailure(transactionID, "rolled_back_state_mismatch", err)
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if err := discardTerminalReceipt(root); err != nil {
			return Result{FailureClass: "terminal_replacement_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
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
		if err := verifyTargetVector(root, plan, 0); err != nil {
			return recoveryObservationFailure(transactionID, "preparing_state_mismatch", err)
		}
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if err := selectRecoveryAction(root, transactionID, action); err != nil {
			return Result{FailureClass: "recovery_action_persistence_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := removeCreatedDirectories(root, plan); err != nil {
			return Result{FailureClass: "directory_cleanup_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := writeMarker(root, rolledBackMarker); err != nil {
			return Result{AppliedCountKnown: true, FailureClass: "terminal_marker_failed", RecoveredBy: RecoveryRollback, State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := discardTerminalReceipt(root); err != nil {
			return Result{FailureClass: "terminal_replacement_failed", RecoveredBy: RecoveryRollback, State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		return runtime.cleanupRecovered(root, plan, StateRolledBack, RecoveryRollback)
	}
	plan, err = loadObjects(root, plan)
	if err != nil {
		return Result{FailureClass: "invalid_staged_objects", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	prefix, err := classifyPrefix(root, plan)
	if err != nil {
		return recoveryObservationFailure(transactionID, "ambiguous_target_state", err)
	}
	if action == RecoveryResume {
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("repository transaction recovery cancelled: %w", err)
		}
		if err := selectRecoveryAction(root, transactionID, action); err != nil {
			return Result{FailureClass: "recovery_action_persistence_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
		}
		if err := discardTerminalReceipt(root); err != nil {
			return Result{FailureClass: "terminal_replacement_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
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
	if err := selectRecoveryAction(root, transactionID, action); err != nil {
		return Result{FailureClass: "recovery_action_persistence_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
	}
	if err := discardTerminalReceipt(root); err != nil {
		return Result{FailureClass: "terminal_replacement_failed", State: StateRecoveryRequired, TransactionID: transactionID}, nil
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
	terminal := Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, RecoveredBy: action, State: state, TransactionID: plan.TransactionID}
	if exists, err := pathExists(root, activeDirectory+"/"+terminalReceiptName); err != nil {
		return Result{FailureClass: "invalid_terminal_receipt", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
	} else if exists {
		receipt, err := loadTerminalReceipt(root, activeDirectory)
		expected, relationErr := terminalReceiptFromResult(plan, receipt.result())
		if err != nil || relationErr != nil || receipt.State != state || !terminalReceiptMatchesPlan(receipt, expected) {
			return Result{FailureClass: "invalid_terminal_receipt", State: StateRecoveryRequired, TransactionID: plan.TransactionID}, nil
		}
		terminal = receipt.result()
	}
	if err := runtime.archiveAndCleanupTerminal(root, plan, terminal); err != nil {
		if errors.Is(err, errCleanupDurabilityUnknown) {
			return Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, FailureClass: state + "_cleanup_durability_unknown", RecoveredBy: action, State: StateDurabilityUnknown, TransactionID: plan.TransactionID}, nil
		}
		return Result{AppliedCount: prefixForState(plan, state), AppliedCountKnown: true, FailureClass: "cleanup_failed", RecoveredBy: action, State: StateCleanupRequired, TransactionID: plan.TransactionID}, nil
	}
	terminal.RecoveredBy = action
	return terminal, nil
}

func (runtime engine) recoverTerminalTombstone(root *os.Root, entries []fs.DirEntry, transactionID, action string) (Result, bool, error) {
	if len(entries) != 1 {
		return Result{}, false, nil
	}
	terminal, found, err := findTerminalControlEntry(entries)
	if err != nil || !found || terminal.TransactionID != transactionID {
		return Result{}, false, nil
	}
	path := ControlDirectory + "/" + terminal.Entry.Name()
	state := terminal.State
	switch state {
	case StateApplied:
		if action != RecoveryResume {
			return Result{FailureClass: "committed_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, true, nil
		}
	case StateRolledBack:
		if action != RecoveryRollback {
			return Result{FailureClass: "rolled_back_state_mismatch", State: StateRecoveryRequired, TransactionID: transactionID}, true, nil
		}
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
	return Result{AppliedCount: receipt.AppliedCount, AppliedCountKnown: true, FailureClass: receipt.FailureClass, RecoveredBy: action, State: state, TransactionID: transactionID}, true, nil
}
