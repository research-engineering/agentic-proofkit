package repositorytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func residueFixture(t *testing.T, root string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, activeDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if content != nil {
		mustWriteTestFile(t, root, journalTemp, string(content), 0o600)
	}
}

func residueObservation(t *testing.T, root string) PreparationResidueObservation {
	t.Helper()
	got, err := InspectPreparationResidue(context.Background(), root)
	if err != nil || got.State != PreparationResidueEligible || len(got.ObservationID) != 71 {
		t.Fatalf("residue observation: %#v %v", got, err)
	}
	return got
}

func residueDestination(token string) string {
	return preparationResidueDirectory + "/quarantined-" + strings.TrimPrefix(token, "sha256:")
}

func residueStat(t *testing.T, root, name string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func residueTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, entry := range snapshotTestTree(t, root) {
		info := residueStat(t, root, entry.Path)
		identity, err := platformFileIdentity(info)
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Path] = identity + ":" + info.Mode().String() + ":" + digest.SHA256BytesRef(entry.Content)
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(filepath.Join(root, entry.Path))
			if err != nil {
				t.Fatal(err)
			}
			result[entry.Path] += digest.SHA256TextRef(target)
		}
	}
	return result
}

func residueAssertError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || errors.Is(err, ErrResidueOutcomeUnverified) {
		t.Fatalf("error=%v, want pre-publication %v", err, want)
	}
}

func TestPreparationResiduePreservesWholeDirectoryAndTerminal(t *testing.T) {
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{"empty", nil}, {"empty-tmp", []byte{}}, {"partial", []byte("{\"unfinished\":")},
		{"binary", []byte{0, 255, 3, 10}}, {"maximum", bytes.Repeat([]byte("x"), MaximumJournalBytes)},
	} {
		for _, retained := range []bool{false, true} {
			name := test.name
			if retained {
				name += "/retained-receipt"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				var old Result
				var terminalPath string
				var terminalBefore map[string]string
				if retained {
					plan, err := BuildPlan(context.Background(), root, []Target{{Path: "old", Content: []byte("retained"), Mode: 0o640}})
					if err != nil {
						t.Fatal(err)
					}
					old, err = Apply(context.Background(), root, plan)
					if err != nil || old.State != StateApplied {
						t.Fatalf("terminal fixture: %#v %v", old, err)
					}
					terminalPath = filepath.Join(root, terminalTombstonePath(old.TransactionID, old.State))
					terminalBefore = residueTree(t, terminalPath)
				}
				residueFixture(t, root, test.content)
				before := residueTree(t, root)
				activeInfo := residueStat(t, root, activeDirectory)
				activeBefore := residueTree(t, filepath.Join(root, activeDirectory))
				observation := residueObservation(t, root)
				if second := residueObservation(t, root); second != observation || !reflect.DeepEqual(before, residueTree(t, root)) {
					t.Fatal("inspection changed evidence or an unchanged observation")
				}
				got, err := QuarantinePreparationResidue(context.Background(), root, observation.ObservationID)
				if err != nil || got.State != PreparationResidueQuarantined || got.ObservationID != observation.ObservationID {
					t.Fatalf("quarantine: %#v %v", got, err)
				}
				moved := residueDestination(observation.ObservationID)
				movedInfo := residueStat(t, root, moved)
				if !os.SameFile(activeInfo, movedInfo) || activeInfo.Mode() != movedInfo.Mode() || !reflect.DeepEqual(activeBefore, residueTree(t, filepath.Join(root, moved))) {
					t.Fatal("whole directory identity, mode or bytes changed")
				}
				if _, err := os.Lstat(filepath.Join(root, activeDirectory)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("active retained: %v", err)
				}
				if retained {
					observed, err := ReadTerminalResult(context.Background(), root, old.TransactionID)
					if err != nil || observed != old || !reflect.DeepEqual(terminalBefore, residueTree(t, terminalPath)) {
						t.Fatalf("old terminal changed: %#v %v", observed, err)
					}
					assertTestFile(t, root, "old", "retained", 0o640)
				}
				postMove := residueTree(t, root)
				if _, err := BuildPlan(context.Background(), root, []Target{{Path: "next", Content: []byte("next"), Mode: 0o600}}); err != nil {
					t.Fatalf("native planning after quarantine: %v", err)
				}
				absent, err := InspectPreparationResidue(context.Background(), root)
				if err != nil || absent != (PreparationResidueObservation{State: PreparationResidueAbsent}) || !reflect.DeepEqual(postMove, residueTree(t, root)) {
					t.Fatalf("planning/absent inspection consumed archive: %#v %v", absent, err)
				}
			})
		}
	}
}

func TestPreparationResidueRejectsRecognizedPlans(t *testing.T) {
	for _, scenario := range []string{"canonical", "wrong-root", "zero-change", "noncanonical"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			planRoot := root
			if scenario == "wrong-root" {
				planRoot = t.TempDir()
			}
			if scenario == "zero-change" {
				mustWriteTestFile(t, root, "target", "after", 0o600)
			}
			plan, err := BuildPlan(context.Background(), planRoot, []Target{{Path: "target", Content: []byte("after"), Mode: 0o600}})
			if err != nil {
				t.Fatal(err)
			}
			content, err := stablejson.Marshal(journalValue(plan))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "noncanonical" {
				content = append([]byte(" \n"), content...)
			}
			residueFixture(t, root, content)
			before := residueTree(t, root)
			got, err := InspectPreparationResidue(context.Background(), root)
			residueAssertError(t, err, ErrResidueIneligible)
			if got != (PreparationResidueObservation{}) {
				t.Fatal("known plan got an observation")
			}
			_, err = QuarantinePreparationResidue(context.Background(), root, digest.SHA256TextRef("not-a-plan-id"))
			residueAssertError(t, err, ErrResidueIneligible)
			if !reflect.DeepEqual(before, residueTree(t, root)) {
				t.Fatal("known evidence changed")
			}
		})
	}
}

func TestPreparationResidueRejectsForbiddenShapes(t *testing.T) {
	for _, scenario := range []string{
		"journal.json", "ready", "ready.tmp", "committed", "rolled-back", "recovery-action.json",
		"recovery-action.tmp", "terminal.json", "terminal.tmp", "after-000.bin", "before-000.bin",
		"publish-000.tmp", "directory-0000.json", "unknown", "Journal.tmp", "extra-entry",
		"tmp-directory", "tmp-symlink", "active-symlink", "tmp-mode", "active-mode", "oversized",
		"invalid-terminal", "conflicting-terminals", "active-alias", "control-alias", "namespace-alias",
	} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, nil)
			switch scenario {
			case "tmp-directory":
				if err := os.Mkdir(filepath.Join(root, journalTemp), 0o700); err != nil {
					t.Fatal(err)
				}
			case "tmp-symlink":
				mustWriteTestFile(t, root, "outside", "private", 0o600)
				if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, journalTemp)); err != nil {
					t.Fatal(err)
				}
			case "active-symlink":
				if err := os.Rename(filepath.Join(root, activeDirectory), filepath.Join(root, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "saved"), filepath.Join(root, activeDirectory)); err != nil {
					t.Fatal(err)
				}
			case "tmp-mode":
				mustWriteTestFile(t, root, journalTemp, "{", 0o644)
			case "active-mode":
				if err := os.Chmod(filepath.Join(root, activeDirectory), 0o750); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				mustWriteTestFile(t, root, journalTemp, strings.Repeat("x", MaximumJournalBytes+1), 0o600)
			case "invalid-terminal", "conflicting-terminals":
				for _, digit := range []string{"1", "2"} {
					name := terminalTombstonePath("sha256:"+strings.Repeat(digit, 64), StateApplied)
					mustWriteTestFile(t, root, name+"/"+terminalReceiptName, "{}", 0o600)
					if scenario == "invalid-terminal" {
						break
					}
				}
			case "active-alias", "control-alias", "namespace-alias":
				from, to := activeDirectory, ControlDirectory+"/Active"
				if scenario == "control-alias" {
					from, to = ControlRoot, ".Agentic-proofkit"
				}
				if scenario == "namespace-alias" {
					from, to = ControlDirectory, ControlRoot+"/Transactions"
				}
				if err := os.Rename(filepath.Join(root, from), filepath.Join(root, to)); err != nil {
					t.Fatal(err)
				}
			case "extra-entry":
				mustWriteTestFile(t, root, journalTemp, "{", 0o600)
				mustWriteTestFile(t, root, activeDirectory+"/unknown", "evidence", 0o600)
			default:
				mustWriteTestFile(t, root, activeDirectory+"/"+scenario, "evidence", 0o600)
			}
			before := residueTree(t, root)
			got, err := InspectPreparationResidue(context.Background(), root)
			residueAssertError(t, err, ErrResidueIneligible)
			if got != (PreparationResidueObservation{}) {
				t.Fatal("unsafe shape got an observation")
			}
			_, err = QuarantinePreparationResidue(context.Background(), root, digest.SHA256TextRef("expected"))
			residueAssertError(t, err, ErrResidueIneligible)
			if !reflect.DeepEqual(before, residueTree(t, root)) {
				t.Fatal("rejection changed evidence")
			}
		})
	}
}

func TestPreparationResidueStaleTokenOperands(t *testing.T) {
	for _, scenario := range []string{"bytes", "size", "tmp-inode", "active-inode", "control-inode", "namespace-inode", "root-inode", "mode", "terminal-added", "terminal-inode", "terminal-bytes", "terminal-file-inode", "terminal-file-mode"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "repository")
			residueFixture(t, root, []byte("partial"))
			terminal := retiredTerminalTombstonePath(digest.SHA256TextRef("terminal"), StateApplied)
			if strings.HasPrefix(scenario, "terminal-") && scenario != "terminal-added" {
				if err := os.Mkdir(filepath.Join(root, terminal), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "terminal-bytes" || strings.HasPrefix(scenario, "terminal-file-") {
				receipt := terminalReceipt{State: StateApplied, AppliedCount: 1, TransactionID: digest.SHA256TextRef("terminal")}
				content, err := stablejson.Marshal(terminalReceiptValue(receipt))
				if err != nil {
					t.Fatal(err)
				}
				mustWriteTestFile(t, root, terminal+"/"+terminalReceiptName, string(content), 0o600)
			}
			observation := residueObservation(t, root)
			replaceParent := func(name, child string) {
				t.Helper()
				old := filepath.Join(root, name)
				if name == "." {
					old = root
				}
				if err := os.Rename(old, old+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(old, 0o700); err != nil {
					t.Fatal(err)
				}
				if child != "" {
					if err := os.Rename(filepath.Join(old+"-saved", child), filepath.Join(old, child)); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch scenario {
			case "bytes":
				mustWriteTestFile(t, root, journalTemp, "changed", 0o600)
			case "size":
				mustWriteTestFile(t, root, journalTemp, "longer-partial", 0o600)
			case "tmp-inode":
				if err := os.Rename(filepath.Join(root, journalTemp), filepath.Join(root, "saved-tmp")); err != nil {
					t.Fatal(err)
				}
				mustWriteTestFile(t, root, journalTemp, "partial", 0o600)
			case "active-inode":
				// Save outside transactions so the only changed admitted operand is active.
				if err := os.Rename(filepath.Join(root, activeDirectory), filepath.Join(root, "saved-active")); err != nil {
					t.Fatal(err)
				}
				residueFixture(t, root, nil)
				if err := os.Rename(filepath.Join(root, "saved-active", "journal.tmp"), filepath.Join(root, journalTemp)); err != nil {
					t.Fatal(err)
				}
			case "control-inode":
				replaceParent(ControlRoot, "transactions")
			case "namespace-inode":
				replaceParent(ControlDirectory, "active")
			case "root-inode":
				replaceParent(".", ControlRoot)
			case "mode":
				if err := os.Chmod(filepath.Join(root, journalTemp), 0o640); err != nil {
					t.Fatal(err)
				}
			case "terminal-added":
				if err := os.Mkdir(filepath.Join(root, terminal), 0o700); err != nil {
					t.Fatal(err)
				}
			case "terminal-inode":
				if err := os.Rename(filepath.Join(root, terminal), filepath.Join(root, "saved-terminal")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, terminal), 0o700); err != nil {
					t.Fatal(err)
				}
			case "terminal-bytes":
				receipt := terminalReceipt{State: StateApplied, AppliedCount: 2, TransactionID: digest.SHA256TextRef("terminal")}
				content, err := stablejson.Marshal(terminalReceiptValue(receipt))
				if err != nil {
					t.Fatal(err)
				}
				mustWriteTestFile(t, root, terminal+"/"+terminalReceiptName, string(content), 0o600)
			case "terminal-file-inode":
				name := filepath.Join(root, terminal, terminalReceiptName)
				content, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(name, filepath.Join(root, "saved-receipt")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, content, 0o600); err != nil {
					t.Fatal(err)
				}
			case "terminal-file-mode":
				if err := os.Chmod(filepath.Join(root, terminal, terminalReceiptName), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			before := residueTree(t, root)
			got, err := QuarantinePreparationResidue(context.Background(), root, observation.ObservationID)
			want := ErrControlStateChanged
			if scenario == "mode" || scenario == "terminal-file-mode" {
				want = ErrResidueIneligible
			}
			residueAssertError(t, err, want)
			if got != (PreparationResidueRelocation{}) || !reflect.DeepEqual(before, residueTree(t, root)) {
				t.Fatal("stale token changed evidence or returned relocation")
			}
		})
	}
}

func TestPreparationResidueMissingNamespaceAndSourceStayReadOnly(t *testing.T) {
	for _, name := range []string{"none", "control-only", "namespace"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if name != "none" {
				directory := ControlRoot
				if name == "namespace" {
					directory = ControlDirectory
				}
				if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			before := residueTree(t, root)
			got, err := InspectPreparationResidue(context.Background(), root)
			if err != nil || got != (PreparationResidueObservation{State: PreparationResidueAbsent}) {
				t.Fatalf("absent: %#v %v", got, err)
			}
			_, err = QuarantinePreparationResidue(context.Background(), root, digest.SHA256TextRef("observation"))
			residueAssertError(t, err, ErrResidueAbsent)
			if !reflect.DeepEqual(before, residueTree(t, root)) {
				t.Fatal("missing state created transaction namespace")
			}
		})
	}
}

func TestPreparationResidueAdmitsTokenBeforeIO(t *testing.T) {
	canonical := "sha256:" + strings.Repeat("1", 64)
	for _, token := range []string{"", "private-input", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("1", 63), " " + canonical, canonical + "\n", "\t" + canonical, canonical + "\u00a0"} {
		operations := nativeResidueOperations()
		operations.openLease = func(context.Context, string, transactionLockMode) (*InspectionLease, error) {
			t.Fatal("invalid token reached I/O")
			return nil, nil
		}
		_, err := quarantinePreparationResidue(context.Background(), "not-an-existing-root", token, operations)
		residueAssertError(t, err, ErrResidueObservationInvalid)
		if strings.Contains(err.Error(), "private-input") {
			t.Fatal("raw input leaked")
		}
	}
}

func TestPreparationResidueLockModesAndBusy(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, nil)
	observation := residueObservation(t, root)
	for _, mode := range []transactionLockMode{transactionReadLock, transactionWriteLock} {
		lease, err := openInspectionLease(context.Background(), root, mode)
		if err != nil {
			t.Fatal(err)
		}
		got, inspectErr := InspectPreparationResidue(context.Background(), root)
		if mode == transactionReadLock {
			if inspectErr != nil || got != observation {
				t.Fatalf("shared readers: %#v %v", got, inspectErr)
			}
		} else {
			residueAssertError(t, inspectErr, ErrBusy)
		}
		_, err = QuarantinePreparationResidue(context.Background(), root, observation.ObservationID)
		residueAssertError(t, err, ErrBusy)
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	operations := nativeResidueOperations()
	operations.barrier = func(point string) error {
		if point == "parent-pinned" {
			reader, err := OpenInspectionLease(context.Background(), root)
			if reader != nil {
				reader.Close()
			}
			residueAssertError(t, err, ErrBusy)
		}
		return nil
	}
	if _, err := quarantinePreparationResidue(context.Background(), root, observation.ObservationID, operations); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationResidueDestinationFirstLostAcknowledgment(t *testing.T) {
	for _, next := range []string{"absent", "eligible", "invalid"} {
		t.Run(next, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, []byte("original evidence"))
			observation := residueObservation(t, root)
			operations := nativeResidueOperations()
			operations.barrier = func(point string) error {
				if point == "published" {
					return errors.New("injected lost acknowledgment")
				}
				return nil
			}
			got, err := quarantinePreparationResidue(context.Background(), root, observation.ObservationID, operations)
			if got != (PreparationResidueRelocation{}) || !errors.Is(err, ErrResidueOutcomeUnverified) || err.Error() != ErrResidueOutcomeUnverified.Error() {
				t.Fatalf("lost acknowledgment: %#v %v", got, err)
			}
			if next != "absent" {
				residueFixture(t, root, []byte("new evidence"))
				if next == "invalid" {
					mustWriteTestFile(t, root, activeDirectory+"/ready", "", 0o600)
				}
			}
			before := residueTree(t, root)
			operations = nativeResidueOperations()
			operations.openFile = func(*InspectionLease, string) (InspectionFile, error) {
				t.Fatal("retry observed new source before destination")
				return nil, nil
			}
			_, err = quarantinePreparationResidue(context.Background(), root, observation.ObservationID, operations)
			residueAssertError(t, err, ErrResidueDestinationPresent)
			if !reflect.DeepEqual(before, residueTree(t, root)) {
				t.Fatal("retry changed archive or new source")
			}
		})
	}
}

func TestPreparationResidueDestinationRoutes(t *testing.T) {
	for _, scenario := range []string{"occupied-empty", "occupied-file", "occupied-symlink", "alias", "parent-alias", "parent-symlink", "parent-mode"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, []byte("evidence"))
			observation := residueObservation(t, root)
			parent := filepath.Join(root, preparationResidueDirectory)
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(root, residueDestination(observation.ObservationID))
			want := ErrResidueIneligible
			switch scenario {
			case "occupied-empty":
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
				want = ErrResidueDestinationPresent
			case "occupied-file":
				if err := os.WriteFile(destination, []byte("retained"), 0o600); err != nil {
					t.Fatal(err)
				}
				want = ErrResidueDestinationPresent
			case "occupied-symlink":
				if err := os.Symlink("untrusted-target", destination); err != nil {
					t.Fatal(err)
				}
				want = ErrResidueDestinationPresent
			case "alias":
				if err := os.Mkdir(filepath.Join(parent, strings.ToUpper(filepath.Base(destination))), 0o700); err != nil {
					t.Fatal(err)
				}
			case "parent-alias":
				if err := os.Rename(parent, filepath.Join(root, ControlRoot, "Transaction-residue")); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Rename(parent, filepath.Join(root, "saved-residue")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "saved-residue"), parent); err != nil {
					t.Fatal(err)
				}
			case "parent-mode":
				if err := os.Chmod(parent, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			before := residueTree(t, root)
			_, err := QuarantinePreparationResidue(context.Background(), root, observation.ObservationID)
			residueAssertError(t, err, want)
			if !reflect.DeepEqual(before, residueTree(t, root)) {
				t.Fatal("destination rejection changed evidence")
			}
		})
	}
}

type residueFaultFile struct {
	InspectionFile
	readErr, closeErr error
	afterRead         func()
}

func (file residueFaultFile) Read(buffer []byte) (int, error) {
	if file.readErr != nil {
		return 0, file.readErr
	}
	n, err := file.InspectionFile.Read(buffer)
	if file.afterRead != nil {
		file.afterRead()
	}
	return n, err
}

func (file residueFaultFile) Close() error {
	return errors.Join(file.InspectionFile.Close(), file.closeErr)
}

func TestPreparationResidueOperationalErrorsNeverEligibility(t *testing.T) {
	for _, action := range []string{"inspect", "quarantine"} {
		for _, fault := range []string{"open", "read", "close", "lease-close", "traversal-close", "cancel-read", "cancel-close"} {
			t.Run(action+"/"+fault, func(t *testing.T) {
				root := t.TempDir()
				residueFixture(t, root, []byte("private-journal-text"))
				observation := residueObservation(t, root)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				operations := nativeResidueOperations()
				injected := errors.New("private-diagnostic-must-not-escape")
				want := ErrResidueOperation
				operations.openFile = func(lease *InspectionLease, name string) (InspectionFile, error) {
					if fault == "open" {
						return nil, injected
					}
					if fault == "traversal-close" {
						return nil, errors.Join(injected, rootpath.ErrTraversalCleanup)
					}
					file, err := lease.OpenExactRegularFile(name)
					if err != nil {
						return nil, err
					}
					wrapped := residueFaultFile{InspectionFile: file}
					switch fault {
					case "read":
						wrapped.readErr = injected
					case "close", "cancel-close":
						wrapped.closeErr = injected
					case "cancel-read":
						wrapped.afterRead = cancel
					}
					if fault == "cancel-close" {
						cancel()
					}
					return wrapped, nil
				}
				if fault == "lease-close" {
					operations.closeLease = func(lease *InspectionLease) error {
						if err := lease.lock.directory.Close(); err != nil {
							t.Fatal(err)
						}
						return lease.Close()
					}
				}
				if fault == "close" || fault == "lease-close" || fault == "cancel-close" {
					want = ErrReadCleanup
				}
				if fault == "traversal-close" {
					want = rootpath.ErrTraversalCleanup
				}
				if fault == "cancel-read" {
					want = context.Canceled
				}
				before := residueTree(t, root)
				var err error
				if action == "inspect" {
					got, inspectErr := inspectPreparationResidue(ctx, root, operations)
					err = inspectErr
					if got != (PreparationResidueObservation{}) {
						t.Fatal("operational error produced observation")
					}
				} else {
					got, mutationErr := quarantinePreparationResidue(ctx, root, observation.ObservationID, operations)
					err = mutationErr
					if got != (PreparationResidueRelocation{}) {
						t.Fatal("operational error produced success")
					}
				}
				published := action == "quarantine" && fault == "lease-close"
				if !errors.Is(err, want) || errors.Is(err, ErrResidueOutcomeUnverified) != published || errors.Is(err, ErrResidueIneligible) || strings.Contains(err.Error(), "private-") {
					t.Fatalf("error classification: %v want=%v published=%v", err, want, published)
				}
				if fault == "cancel-close" && !errors.Is(err, context.Canceled) {
					t.Fatal("cleanup lost cancellation")
				}
				if !published && !reflect.DeepEqual(before, residueTree(t, root)) {
					t.Fatal("read failure changed evidence")
				}
			})
		}
	}
}

func TestPreparationResidueDeterministicReobservationBarriers(t *testing.T) {
	for _, scenario := range []string{"bytes", "mode", "inode", "root", "namespace-appearance", "cancel", "parent-replacement", "destination-appearance"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "repository")
			residueFixture(t, root, []byte("partial"))
			observation := residueObservation(t, root)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			operations := nativeResidueOperations()
			fired := false
			point := "reobserve"
			if scenario == "parent-replacement" || scenario == "destination-appearance" {
				point = "parent-pinned"
			}
			if scenario == "namespace-appearance" {
				root = t.TempDir()
			}
			operations.barrier = func(reached string) error {
				if reached != point || fired {
					return nil
				}
				fired = true
				switch scenario {
				case "bytes":
					mustWriteTestFile(t, root, journalTemp, "changed", 0o600)
				case "mode":
					if err := os.Chmod(filepath.Join(root, journalTemp), 0o644); err != nil {
						t.Fatal(err)
					}
				case "inode":
					if err := os.Rename(filepath.Join(root, journalTemp), filepath.Join(root, "saved")); err != nil {
						t.Fatal(err)
					}
					mustWriteTestFile(t, root, journalTemp, "partial", 0o600)
				case "root":
					if err := os.Rename(root, root+"-saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(root, 0o700); err != nil {
						t.Fatal(err)
					}
				case "namespace-appearance":
					residueFixture(t, root, nil)
				case "cancel":
					cancel()
				case "parent-replacement":
					parent := filepath.Join(root, preparationResidueDirectory)
					if err := os.Rename(parent, parent+"-saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(parent, 0o700); err != nil {
						t.Fatal(err)
					}
				case "destination-appearance":
					if err := os.Mkdir(filepath.Join(root, residueDestination(observation.ObservationID)), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			var err error
			if point == "parent-pinned" {
				_, err = quarantinePreparationResidue(ctx, root, observation.ObservationID, operations)
			} else {
				_, err = inspectPreparationResidue(ctx, root, operations)
			}
			want := ErrControlStateChanged
			if scenario == "mode" {
				want = ErrResidueIneligible
			}
			if scenario == "cancel" {
				want = context.Canceled
			}
			if scenario == "destination-appearance" {
				want = ErrResidueDestinationPresent
			}
			residueAssertError(t, err, want)
			if !fired {
				t.Fatal("barrier not reached")
			}
		})
	}
}

func TestPreparationResidueFilesystemOperands(t *testing.T) {
	for _, rejected := range []string{"control", "active"} {
		t.Run(rejected, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, []byte("retained"))
			observation := residueObservation(t, root)
			control := residueStat(t, root, ControlDirectory)
			active := residueStat(t, root, activeDirectory)
			before := residueTree(t, filepath.Join(root, activeDirectory))
			operations := nativeResidueOperations()
			var compared []string
			operations.sameFilesystem = func(left, right os.FileInfo) (bool, error) {
				parent := residueStat(t, root, preparationResidueDirectory)
				if !os.SameFile(right, parent) {
					t.Fatal("filesystem comparison omitted destination parent")
				}
				var operand string
				switch {
				case os.SameFile(left, control):
					operand = "control"
				case os.SameFile(left, active):
					operand = "active"
				default:
					t.Fatal("filesystem comparison used an unrelated source")
				}
				compared = append(compared, operand)
				return operand != rejected, nil
			}
			got, err := quarantinePreparationResidue(context.Background(), root, observation.ObservationID, operations)
			residueAssertError(t, err, ErrResidueFilesystem)
			if got != (PreparationResidueRelocation{}) {
				t.Fatalf("filesystem rejection returned relocation: %#v", got)
			}
			wantCompared := []string{"control"}
			if rejected == "active" {
				wantCompared = append(wantCompared, "active")
			}
			if !reflect.DeepEqual(compared, wantCompared) {
				t.Fatalf("filesystem operands = %v, want %v", compared, wantCompared)
			}
			after := residueStat(t, root, activeDirectory)
			if !os.SameFile(active, after) || active.Mode() != after.Mode() || !reflect.DeepEqual(before, residueTree(t, filepath.Join(root, activeDirectory))) {
				t.Fatal("filesystem rejection changed retained source evidence")
			}
			if _, err := os.Lstat(filepath.Join(root, residueDestination(observation.ObservationID))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("filesystem rejection relocated evidence: %v", err)
			}
		})
	}
}

func TestPreparationResiduePostPublicationFailures(t *testing.T) {
	for _, fault := range []string{"source-sync", "destination-sync", "readback", "cancel", "terminal-change", "parent-change"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, []byte("retained"))
			observation := residueObservation(t, root)
			active := residueStat(t, root, activeDirectory)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			operations := nativeResidueOperations()
			var synced []string
			operations.syncParent = func(root *os.Root, name string) error {
				synced = append(synced, name)
				if fault == "source-sync" && name == ControlDirectory || fault == "destination-sync" && name == preparationResidueDirectory {
					return errors.New("injected sync")
				}
				return syncDirectory(root, name)
			}
			operations.barrier = func(point string) error {
				if point != "published" {
					return nil
				}
				switch fault {
				case "cancel":
					cancel()
				case "terminal-change":
					name := retiredTerminalTombstonePath(digest.SHA256TextRef("added"), StateApplied)
					if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
						t.Fatal(err)
					}
				case "parent-change":
					if err := os.Chmod(filepath.Join(root, preparationResidueDirectory), 0o750); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			// Function values are frozen per call; the wrapper observes the barrier flag.
			readback := false
			if fault == "readback" {
				operations.barrier = func(point string) error {
					if point == "published" {
						readback = true
					}
					return nil
				}
				operations.openFile = func(lease *InspectionLease, name string) (InspectionFile, error) {
					if readback {
						return nil, io.ErrUnexpectedEOF
					}
					return lease.OpenExactRegularFile(name)
				}
			}
			got, err := quarantinePreparationResidue(ctx, root, observation.ObservationID, operations)
			if got != (PreparationResidueRelocation{}) || !errors.Is(err, ErrResidueOutcomeUnverified) || err.Error() != ErrResidueOutcomeUnverified.Error() {
				t.Fatalf("post-publication error: %#v %v", got, err)
			}
			if !reflect.DeepEqual(synced, []string{ControlDirectory, preparationResidueDirectory}) {
				t.Fatalf("did not sync both parents: %v", synced)
			}
			moved := residueDestination(observation.ObservationID)
			if !os.SameFile(active, residueStat(t, root, moved)) {
				t.Fatal("published evidence identity changed")
			}
			assertTestFile(t, root, moved+"/journal.tmp", "retained", 0o600)
			if _, err := os.Lstat(filepath.Join(root, activeDirectory)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("error restored active")
			}
		})
	}
}

func TestPreparationResidueNumericOwnershipOperand(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, []byte("partial"))
	value, err := residueNodeValue(residueStat(t, root, journalTemp), "journal.tmp", false)
	if err != nil {
		t.Fatal(err)
	}
	if value["ownerId"] != json.Number(intString(os.Geteuid())) {
		t.Fatal("owner identity must be numeric, not boolean")
	}
	before, err := digest.StableJSONSHA256Ref(value)
	if err != nil {
		t.Fatal(err)
	}
	value["ownerId"] = json.Number(intString(os.Geteuid() + 1))
	after, err := digest.StableJSONSHA256Ref(value)
	if err != nil || before == after {
		t.Fatal("numeric owner is not an independent digest operand")
	}
}
