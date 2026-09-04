package repositorytransaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var errCleanupDurabilityUnknown = errors.New("repository transaction cleanup durability is unknown")

func cleanupActive(root *os.Root, plan *Plan) error {
	return cleanupTransactionDirectory(root, activeDirectory, plan, false, nil)
}

func (runtime engine) archiveAndCleanupTerminal(root *os.Root, plan Plan, state string) error {
	tombstone, err := archiveTerminal(root, plan, state)
	if err != nil {
		return err
	}
	return runtime.compactTerminalTombstone(root, tombstone, &plan)
}

func archiveTerminal(root *os.Root, plan Plan, state string) (string, error) {
	if state != StateApplied && state != StateRolledBack {
		return "", fmt.Errorf("repository transaction terminal state is invalid")
	}
	tombstone := terminalTombstonePath(plan.TransactionID, state)
	if exists, err := pathExists(root, tombstone); err != nil {
		return "", err
	} else if exists {
		return "", fmt.Errorf("repository transaction terminal tombstone already exists")
	}
	if err := ensureTerminalReceipt(root, plan, state); err != nil {
		return "", err
	}
	if err := root.Rename(filepath.FromSlash(activeDirectory), filepath.FromSlash(tombstone)); err != nil {
		return "", fmt.Errorf("archive repository transaction terminal state")
	}
	if err := syncDirectory(root, ControlDirectory); err != nil {
		return "", err
	}
	return tombstone, nil
}

func (runtime engine) cleanupTerminalTombstone(root *os.Root, tombstone string) error {
	return runtime.compactTerminalTombstone(root, tombstone, nil)
}

func (runtime engine) compactTerminalTombstone(root *os.Root, tombstone string, plan *Plan) error {
	entries, err := transactionEntries(root, tombstone)
	if err != nil {
		return err
	}
	if err := validateTransactionEntries(entries, plan, true); err != nil {
		return err
	}
	receipt, err := loadTerminalReceipt(root, tombstone)
	if err != nil {
		return err
	}
	transactionID, state, ok := terminalEntryIdentity(filepath.Base(tombstone))
	if !ok || receipt.TransactionID != transactionID || receipt.State != state {
		return fmt.Errorf("repository transaction terminal receipt does not match its route")
	}
	if plan != nil && (receipt.TransactionID != plan.TransactionID || receipt.AppliedCount != prefixForState(*plan, state)) {
		return fmt.Errorf("repository transaction terminal receipt does not match its plan")
	}
	for _, entry := range entries {
		if entry.Name() == terminalReceiptName {
			continue
		}
		if err := root.Remove(filepath.FromSlash(tombstone + "/" + entry.Name())); err != nil {
			return fmt.Errorf("remove repository transaction artifact")
		}
	}
	if err := syncDirectory(root, tombstone); err != nil {
		return fmt.Errorf("%w: terminal receipt content sync failed", errCleanupDurabilityUnknown)
	}
	if err := runtime.callFault(faultAfterStateRemoval, -1); err != nil {
		return fmt.Errorf("%w: terminal receipt compaction interrupted", errCleanupDurabilityUnknown)
	}
	if err := syncDirectory(root, ControlDirectory); err != nil {
		return fmt.Errorf("%w: terminal receipt route sync failed", errCleanupDurabilityUnknown)
	}
	return nil
}

func discardTerminalReceipt(root *os.Root) error {
	entries, err := controlEntries(root)
	if err != nil || len(entries) == 0 {
		return err
	}
	if len(entries) != 1 {
		return fmt.Errorf("repository transaction control directory contains conflicting state")
	}
	entry := entries[0]
	transactionID, state, ok := terminalEntryIdentity(entry.Name())
	if !ok || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
		return fmt.Errorf("repository transaction terminal receipt is invalid")
	}
	tombstone := ControlDirectory + "/" + entry.Name()
	children, err := transactionEntries(root, tombstone)
	if err != nil || len(children) != 1 || children[0].Name() != terminalReceiptName {
		return fmt.Errorf("repository transaction terminal receipt requires recovery")
	}
	receipt, err := loadTerminalReceipt(root, tombstone)
	if err != nil || receipt.TransactionID != transactionID || receipt.State != state {
		return fmt.Errorf("repository transaction terminal receipt is invalid")
	}
	if err := root.Remove(filepath.FromSlash(tombstone + "/" + terminalReceiptName)); err != nil {
		return fmt.Errorf("remove previous repository transaction terminal receipt content")
	}
	if err := syncDirectory(root, tombstone); err != nil {
		return err
	}
	if err := root.Remove(filepath.FromSlash(tombstone)); err != nil {
		return fmt.Errorf("remove previous repository transaction terminal receipt")
	}
	return syncDirectory(root, ControlDirectory)
}

func cleanupTransactionDirectory(root *os.Root, directory string, plan *Plan, allowPartialTerminal bool, afterRemoval func() error) error {
	entries, err := transactionEntries(root, directory)
	if err != nil {
		return err
	}
	if err := validateTransactionEntries(entries, plan, allowPartialTerminal); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := root.Remove(filepath.FromSlash(directory + "/" + entry.Name())); err != nil {
			return fmt.Errorf("remove repository transaction artifact")
		}
	}
	if err := root.Remove(filepath.FromSlash(directory)); err != nil {
		return fmt.Errorf("remove repository transaction state")
	}
	if afterRemoval != nil {
		if err := afterRemoval(); err != nil {
			return fmt.Errorf("%w: %v", errCleanupDurabilityUnknown, err)
		}
	}
	if err := syncDirectory(root, ControlDirectory); err != nil {
		return fmt.Errorf("%w: %v", errCleanupDurabilityUnknown, err)
	}
	return nil
}
