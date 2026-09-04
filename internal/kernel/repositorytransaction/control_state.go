package repositorytransaction

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type terminalControlIdentity struct {
	Entry         fs.DirEntry
	Retired       bool
	State         string
	TransactionID string
}

func validateActiveState(root *os.Root, plan Plan) error {
	if err := validateActivePlan(plan); err != nil {
		return err
	}
	entries, err := activeEntries(root)
	if err != nil {
		return err
	}
	return validateTransactionEntries(entries, &plan, false)
}

func validateTransactionEntries(entries []fs.DirEntry, plan *Plan, allowPartialTerminal bool) error {
	allowed := map[string]struct{}{
		"journal.json":          {},
		"journal.tmp":           {},
		"ready":                 {},
		"ready.tmp":             {},
		"committed":             {},
		"committed.tmp":         {},
		"rolled-back":           {},
		"rolled-back.tmp":       {},
		"recovery-action.json":  {},
		"recovery-action.tmp":   {},
		terminalReceiptName:     {},
		terminalReceiptTempName: {},
	}
	if plan != nil {
		for index, operation := range plan.Operations {
			if operation.Action == ActionUnchanged {
				continue
			}
			allowed[strings.TrimPrefix(afterObjectPath(index), activeDirectory+"/")] = struct{}{}
			allowed[strings.TrimPrefix(transactionTemporaryPath(plan.TransactionID, index, operation.Path), activeDirectory+"/")] = struct{}{}
			if operation.Before.Exists {
				allowed[strings.TrimPrefix(beforeObjectPath(index), activeDirectory+"/")] = struct{}{}
			}
		}
		for index := range plan.CreatedDirectories {
			allowed[strings.TrimPrefix(directoryOwnershipPath(index), activeDirectory+"/")] = struct{}{}
			allowed[strings.TrimPrefix(directoryOwnershipTempPath(index), activeDirectory+"/")] = struct{}{}
		}
	}
	for _, entry := range entries {
		_, explicitlyAllowed := allowed[entry.Name()]
		if allowPartialTerminal && plan == nil {
			explicitlyAllowed = explicitlyAllowed || isBoundedTransactionEntryName(entry.Name())
		}
		if !explicitlyAllowed || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("repository transaction control directory contains an unknown entry")
		}
	}
	return nil
}

func activeEntries(root *os.Root) ([]fs.DirEntry, error) {
	return transactionEntries(root, activeDirectory)
}

func transactionEntries(root *os.Root, relativePath string) ([]fs.DirEntry, error) {
	if err := validatePrivateDirectory(root, relativePath, 0o700); err != nil {
		return nil, err
	}
	directory, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		return nil, fmt.Errorf("open repository transaction state")
	}
	defer directory.Close()
	entryLimit := MaximumOperations*2 + MaximumOperations*pathidentity.MaximumComponents + 10
	entries, err := directory.ReadDir(entryLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read repository transaction state")
	}
	if len(entries) > entryLimit {
		return nil, fmt.Errorf("repository transaction state exceeds its entry limit")
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	return entries, nil
}

func hasPendingTransactionState(root *os.Root) (bool, error) {
	pending, err := pendingTransactionState(root)
	return pending.Exists, err
}

func pendingTransactionState(root *os.Root) (pendingState, error) {
	exists, err := controlNamespaceExists(root)
	if err != nil || !exists {
		return pendingState{}, err
	}
	entries, err := controlEntries(root)
	if err != nil {
		return pendingState{}, err
	}
	if len(entries) == 0 {
		return pendingState{}, nil
	}
	pending := pendingState{Exists: true}
	active := false
	for _, entry := range entries {
		if entry.Name() == "active" && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			if active {
				return pending, nil
			}
			active = true
		}
	}
	if active {
		if _, _, err := findTerminalControlEntry(entries); err != nil {
			return pending, nil
		}
		if err := validatePrivateDirectory(root, activeDirectory, 0o700); err != nil {
			return pendingState{}, err
		}
		if plan, loadErr := loadJournal(root); loadErr == nil {
			pending.TransactionID = plan.TransactionID
			return pending, nil
		}
		if plan, admitted, inspectErr := loadPreparingJournal(root); inspectErr == nil && admitted {
			pending.TransactionID = plan.TransactionID
		}
		return pending, nil
	}
	if len(entries) != 1 {
		return pending, nil
	}
	entry := entries[0]
	if transactionID, state, retired, ok := controlTerminalEntryIdentity(entry.Name()); ok && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
		children, inspectErr := transactionEntries(root, ControlDirectory+"/"+entry.Name())
		if inspectErr != nil {
			return pendingState{}, inspectErr
		}
		if retired && len(children) == 0 {
			return pendingState{}, nil
		}
		if len(children) == 1 && children[0].Name() == terminalReceiptName {
			receipt, receiptErr := loadTerminalReceipt(root, ControlDirectory+"/"+entry.Name())
			if receiptErr == nil && receipt.TransactionID == transactionID && receipt.State == state {
				return pendingState{}, nil
			}
		}
		pending.TransactionID = transactionID
	}
	return pending, nil
}

func controlEntries(root *os.Root) ([]fs.DirEntry, error) {
	exists, err := controlNamespaceExists(root)
	if err != nil {
		return nil, err
	}
	if !exists {
		return []fs.DirEntry{}, nil
	}
	directory, err := root.Open(filepath.FromSlash(ControlDirectory))
	if err != nil {
		return nil, fmt.Errorf("open repository transaction control directory")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read repository transaction control directory")
	}
	if len(entries) > 3 {
		return nil, fmt.Errorf("repository transaction control directory contains conflicting state")
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	return entries, nil
}

func controlTerminalEntryIdentity(name string) (string, string, bool, bool) {
	if transactionID, state, ok := terminalEntryIdentity(name); ok {
		return transactionID, state, false, true
	}
	if transactionID, state, ok := terminalEntryIdentity(strings.TrimPrefix(name, "retired-")); strings.HasPrefix(name, "retired-") && ok {
		return transactionID, state, true, true
	}
	return "", "", false, false
}

func findTerminalControlEntry(entries []fs.DirEntry) (terminalControlIdentity, bool, error) {
	activeSeen := false
	var terminal terminalControlIdentity
	terminalSeen := false
	for _, entry := range entries {
		if entry.Name() == "active" {
			if activeSeen || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return terminalControlIdentity{}, false, fmt.Errorf("repository transaction active control route is invalid")
			}
			activeSeen = true
			continue
		}
		transactionID, state, retired, ok := controlTerminalEntryIdentity(entry.Name())
		if !ok || terminalSeen || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return terminalControlIdentity{}, false, fmt.Errorf("repository transaction terminal control route is invalid")
		}
		terminal = terminalControlIdentity{Entry: entry, Retired: retired, State: state, TransactionID: transactionID}
		terminalSeen = true
	}
	return terminal, terminalSeen, nil
}

func terminalEntryIdentity(name string) (string, string, bool) {
	for _, state := range []string{StateApplied, StateRolledBack} {
		prefix := "gc-"
		suffix := "-" + state
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		hexDigest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		transactionID, err := admit.SHA256Ref("sha256:"+hexDigest, "repository transaction terminal identity")
		if err == nil {
			return transactionID, state, true
		}
	}
	return "", "", false
}

func terminalTombstonePath(transactionID, state string) string {
	return ControlDirectory + "/gc-" + strings.TrimPrefix(transactionID, "sha256:") + "-" + state
}

func retiredTerminalTombstonePath(transactionID, state string) string {
	return ControlDirectory + "/retired-gc-" + strings.TrimPrefix(transactionID, "sha256:") + "-" + state
}

func isBoundedTransactionEntryName(name string) bool {
	for _, prefix := range []string{"after-", "before-"} {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".bin") {
			indexText := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".bin")
			index, err := strconv.Atoi(indexText)
			return err == nil && len(indexText) == 3 && index >= 0 && index < MaximumOperations
		}
	}
	if strings.HasPrefix(name, "directory-") && strings.HasSuffix(name, ".json") {
		indexText := strings.TrimSuffix(strings.TrimPrefix(name, "directory-"), ".json")
		index, err := strconv.Atoi(indexText)
		return err == nil && len(indexText) == 4 && index >= 0 && index < MaximumOperations*pathidentity.MaximumComponents
	}
	if strings.HasPrefix(name, "directory-") && strings.HasSuffix(name, ".tmp") {
		indexText := strings.TrimSuffix(strings.TrimPrefix(name, "directory-"), ".tmp")
		index, err := strconv.Atoi(indexText)
		return err == nil && len(indexText) == 4 && index >= 0 && index < MaximumOperations*pathidentity.MaximumComponents
	}
	if strings.HasPrefix(name, "publish-") && strings.HasSuffix(name, ".tmp") {
		indexText := strings.TrimSuffix(strings.TrimPrefix(name, "publish-"), ".tmp")
		index, err := strconv.Atoi(indexText)
		return err == nil && len(indexText) == 3 && index >= 0 && index < MaximumOperations
	}
	return false
}

func loadPreparingJournal(root *os.Root) (Plan, bool, error) {
	ready, err := markerExists(root, readyMarker)
	if err == nil && ready {
		return Plan{}, false, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Plan{}, false, err
	}
	entries, err := activeEntries(root)
	if err != nil {
		return Plan{}, false, err
	}
	for _, entry := range entries {
		if entry.Name() != "journal.tmp" || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return Plan{}, false, nil
		}
	}
	if len(entries) == 0 {
		return Plan{}, false, nil
	}
	content, err := readOwnedFile(root, journalTemp, MaximumJournalBytes)
	if err != nil {
		return Plan{}, false, err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), MaximumJournalBytes)
	if err != nil {
		return Plan{}, false, nil
	}
	plan, err := admitJournal(value)
	if err != nil {
		return Plan{}, false, nil
	}
	canonical, err := stablejson.Marshal(journalValue(plan))
	if err != nil || !bytes.Equal(content, canonical) {
		return Plan{}, false, nil
	}
	return plan, true, nil
}
