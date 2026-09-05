package repositorytransaction

import (
	"context"
	"errors"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var ErrReplayMismatch = errors.New("repository transaction replay identity or current state does not match")

// ReplayApplied verifies a native no-change plan and an exact prior applied
// receipt under one cooperative lock. Unlike ReadTerminalResult, it rejects
// pending work and stale target observations before acknowledging satisfaction.
func ReplayApplied(ctx context.Context, rootPath string, plan Plan, transactionID string) (result Result, returnErr error) {
	expected, err := admit.SHA256Ref(transactionID, "repository transaction replay identity")
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction replay cancelled: %w", err)
	}
	plan = clonePlan(plan)
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeReadResource(root, "transaction replay root"))
	}()
	if err := validateExecutablePlan(plan, rootID); err != nil {
		return Result{}, err
	}
	if changedCount(plan) != 0 {
		return Result{}, fmt.Errorf("repository transaction replay requires a no-change plan")
	}
	lock, exists, err := acquireExistingTransactionLock(root)
	if err != nil {
		return Result{}, err
	}
	if !exists {
		return Result{}, ErrReplayMismatch
	}
	defer func() {
		if err := lock.releaseChecked(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%w: transaction replay lock", ErrReadCleanup))
		}
	}()
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("repository transaction replay cancelled: %w", err)
	}
	if pending, err := pendingTransactionState(root); err != nil {
		return Result{}, err
	} else if pending.Exists {
		return Result{}, &RecoveryRequiredError{TransactionID: pending.TransactionID}
	}
	if err := verifyTargetVector(root, plan, 0); err != nil {
		if errors.Is(err, errTargetSnapshotChanged) {
			return Result{}, ErrReplayMismatch
		}
		return Result{}, err
	}
	terminal, err := readRetainedTerminalReceipt(root, expected)
	if err != nil {
		return Result{}, err
	}
	if terminal.State != StateApplied || terminal.DesiredStateID != plan.DesiredStateID {
		return Result{}, ErrReplayMismatch
	}
	return Result{AppliedCountKnown: true, State: StateAlreadySatisfied, TransactionID: expected}, nil
}
