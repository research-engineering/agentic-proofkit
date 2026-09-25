package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type cleanupDirectoryReader struct {
	entries  []fs.DirEntry
	readErr  error
	closeErr error
	requests []int
	closes   int
}

func (reader *cleanupDirectoryReader) ReadDir(count int) ([]fs.DirEntry, error) {
	reader.requests = append(reader.requests, count)
	return reader.entries, reader.readErr
}

func (reader *cleanupDirectoryReader) Close() error {
	reader.closes++
	return reader.closeErr
}

func TestControlEntriesReadCleanup(t *testing.T) {
	path := t.TempDir()
	for _, name := range []string{"Z", "a", "b", "\u00e9"} {
		if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		entries []fs.DirEntry
		readErr error
		want    []string
		wantErr string
	}{
		{name: "empty", want: []string{}},
		{name: "EOF", readErr: io.EOF, want: []string{}},
		{name: "raw-name-order", entries: []fs.DirEntry{entries[3], entries[1], entries[0]}, want: []string{"Z", "a", "\u00e9"}},
		{name: "entries-with-EOF", entries: entries[:3], readErr: io.EOF, want: []string{"Z", "a", "b"}},
		{name: "read-failure", entries: entries[:1], readErr: errors.New("caller-private-read"), wantErr: "read repository transaction control directory"},
		{name: "limit", entries: entries, wantErr: "repository transaction control directory contains conflicting state"},
	} {
		for _, failClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/close-fails=%t", test.name, failClose), func(t *testing.T) {
				reader := &cleanupDirectoryReader{entries: append([]fs.DirEntry(nil), test.entries...), readErr: test.readErr}
				if failClose {
					reader.closeErr = &os.PathError{Op: "close", Path: "caller-private-path", Err: errors.New("caller-private-close")}
				}
				got, err := readControlEntries(reader)
				if !reflect.DeepEqual(reader.requests, []int{4}) || reader.closes != 1 {
					t.Fatalf("read requests=%v closes=%d", reader.requests, reader.closes)
				}
				if failClose {
					if got != nil || !errors.Is(err, ErrReadCleanup) || err.Error() != "repository read cleanup failed: control directory" {
						t.Fatalf("cleanup result=%v error=%v", got, err)
					}
					if errors.Is(err, reader.closeErr) || errors.Is(err, ErrRecoveryRequired) {
						t.Fatalf("cleanup exposed raw cause or recovery: %v", err)
					}
					return
				}
				if test.wantErr != "" {
					if got != nil || err == nil || err.Error() != test.wantErr || errors.Is(err, ErrReadCleanup) {
						t.Fatalf("read result=%v error=%v", got, err)
					}
					return
				}
				names := make([]string, 0, len(got))
				for _, entry := range got {
					names = append(names, entry.Name())
				}
				if err != nil || !reflect.DeepEqual(names, test.want) {
					t.Fatalf("names=%v want=%v error=%v", names, test.want, err)
				}
			})
		}
	}
}

func TestPendingStateCleanupDominatesLoadedIdentity(t *testing.T) {
	for _, state := range []string{"journal", "preparing", "terminal", "retired-terminal"} {
		for _, errorKind := range []string{"cleanup", "wrapped-cleanup", "traversal-cleanup", "wrapped-traversal-cleanup", "ordinary"} {
			t.Run(state+"/"+errorKind, func(t *testing.T) {
				_, root, original := pendingCleanupFixture(t, state)
				readErr := error(ErrReadCleanup)
				if strings.Contains(errorKind, "traversal") {
					readErr = rootpath.ErrTraversalCleanup
				}
				cleanupClass := readErr
				if strings.HasPrefix(errorKind, "wrapped-") {
					readErr = fmt.Errorf("pending read: %w", readErr)
				} else if errorKind == "ordinary" {
					readErr = errors.New("caller-private-malformed-state")
				}
				calls, fallbacks := 0, 0
				readers := pendingStateReaders{
					journal: loadJournal,
					preparingJournal: func(root *os.Root) (Plan, bool, error) {
						fallbacks++
						return loadPreparingJournal(root)
					},
					terminalReceipt: loadTerminalReceipt,
				}
				switch state {
				case "journal":
					readers.journal = func(root *os.Root) (Plan, error) {
						plan, err := loadJournal(root)
						if err != nil || plan.TransactionID != original.TransactionID {
							t.Fatalf("native journal control: %v", err)
						}
						calls++
						return plan, readErr
					}
				case "preparing":
					readers.preparingJournal = func(root *os.Root) (Plan, bool, error) {
						plan, admitted, err := loadPreparingJournal(root)
						if err != nil || !admitted || plan.TransactionID != original.TransactionID {
							t.Fatalf("native preparing control: admitted=%t error=%v", admitted, err)
						}
						calls++
						return plan, admitted, readErr
					}
				default:
					readers.terminalReceipt = func(root *os.Root, directory string) (terminalReceipt, error) {
						receipt, err := loadTerminalReceipt(root, directory)
						if err != nil || receipt.TransactionID != original.TransactionID {
							t.Fatalf("native receipt control: %v", err)
						}
						calls++
						return receipt, readErr
					}
				}
				pending, err := pendingTransactionStateWithReaders(root, readers)
				if calls != 1 {
					t.Fatalf("selected reader calls=%d", calls)
				}
				if errorKind == "ordinary" {
					want := pendingState{Exists: true}
					if strings.Contains(state, "terminal") {
						want.TransactionID = original.TransactionID
					}
					if pending != want || err != nil || state == "journal" && fallbacks != 1 {
						t.Fatalf("ordinary failure changed: pending=%#v error=%v fallbacks=%d", pending, err, fallbacks)
					}
					return
				}
				id, known := RecoveryTransactionID(err)
				if pending != (pendingState{}) || !errors.Is(err, cleanupClass) || err != readErr || errors.Is(err, ErrRecoveryRequired) || id != "" || known || fallbacks != 0 {
					t.Fatalf("cleanup classification: pending=%#v error=%v id=%q known=%t fallbacks=%d", pending, err, id, known, fallbacks)
				}
			})
		}
	}
}

func TestPendingStateNativeClassificationPreserved(t *testing.T) {
	for _, test := range []struct {
		state   string
		pending bool
		known   bool
	}{
		{state: "absent"}, {state: "empty"},
		{state: "unknown", pending: true}, {state: "empty-active", pending: true},
		{state: "malformed-journal", pending: true}, {state: "malformed-preparing", pending: true},
		{state: "journal", pending: true, known: true}, {state: "preparing", pending: true, known: true},
		{state: "terminal"}, {state: "retired-terminal"}, {state: "retired-empty"},
		{state: "malformed-terminal", pending: true, known: true},
		{state: "mismatched-terminal", pending: true, known: true},
	} {
		t.Run(test.state, func(t *testing.T) {
			rootPath, root, original := pendingCleanupFixture(t, test.state)
			want := pendingState{Exists: test.pending}
			if test.known {
				want.TransactionID = original.TransactionID
			}
			pending, err := pendingTransactionState(root)
			if err != nil || pending != want {
				t.Fatalf("pending=%#v want=%#v error=%v", pending, want, err)
			}
			plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "target", Content: []byte("desired"), Mode: 0o644}})
			id, known := RecoveryTransactionID(err)
			if test.pending {
				if !reflect.DeepEqual(plan, Plan{}) || !errors.Is(err, ErrRecoveryRequired) || errors.Is(err, ErrReadCleanup) || known != test.known || id != want.TransactionID {
					t.Fatalf("recovery changed: plan=%#v error=%v id=%q known=%t", plan, err, id, known)
				}
			} else if err != nil || !reflect.DeepEqual(plan, original) {
				t.Fatalf("clean plan changed: plan=%#v error=%v", plan, err)
			}
			if err != nil && strings.Contains(err.Error(), "caller-private") {
				t.Fatalf("error disclosed caller state: %v", err)
			}
			if test.state == "absent" {
				if _, err := root.Lstat(ControlRoot); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("planning created control namespace: %v", err)
				}
			}
		})
	}
}

func pendingCleanupFixture(t *testing.T, state string) (string, *os.Root, Plan) {
	t.Helper()
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "target", Content: []byte("desired"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if state == "absent" {
		return rootPath, root, plan
	}
	if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	switch state {
	case "empty":
	case "unknown":
		if err := writeOwnedFile(root, ControlDirectory+"/caller-private-name", []byte("caller-private-content"), 0o600); err != nil {
			t.Fatal(err)
		}
	case "empty-active", "malformed-journal", "malformed-preparing":
		if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if state != "empty-active" {
			path := journalPath
			if state == "malformed-preparing" {
				path = journalTemp
			}
			if err := writeOwnedFile(root, path, []byte("caller-private-malformed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	case "journal", "preparing":
		if err := prepareJournal(root, plan); err != nil {
			t.Fatal(err)
		}
		if state == "preparing" {
			if err := root.Rename(journalPath, journalTemp); err != nil {
				t.Fatal(err)
			}
		}
	case "terminal", "retired-terminal", "retired-empty", "malformed-terminal", "mismatched-terminal":
		path := terminalTombstonePath(plan.TransactionID, StateApplied)
		if strings.HasPrefix(state, "retired-") {
			path = retiredTerminalTombstonePath(plan.TransactionID, StateApplied)
		}
		if err := ensureDirectory(root, path, 0o700); err != nil {
			t.Fatal(err)
		}
		if state != "retired-empty" {
			receipt := terminalReceipt{AppliedCount: 1, DesiredStateID: plan.DesiredStateID, State: StateApplied, TransactionID: plan.TransactionID}
			if state == "mismatched-terminal" {
				receipt.TransactionID = "sha256:" + strings.Repeat("0", 64)
			}
			content, err := stablejson.Marshal(terminalReceiptValue(receipt))
			if err != nil {
				t.Fatal(err)
			}
			if state == "malformed-terminal" {
				content = []byte("caller-private-malformed")
			}
			if err := writeOwnedFile(root, path+"/"+terminalReceiptName, content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	default:
		t.Fatalf("unknown fixture state %q", state)
	}
	return rootPath, root, plan
}
