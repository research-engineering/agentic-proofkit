package repositorytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestInspectControlStateClassifiesOwnerStates(t *testing.T) {
	t.Run("absent is clean", func(t *testing.T) {
		rootPath := t.TempDir()
		inspection, err := InspectControlState(context.Background(), rootPath)
		assertControlInspection(t, inspection, err, ControlStateClean, "")
		if _, err := os.Stat(filepath.Join(rootPath, ControlRoot)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only inspection created control state: %v", err)
		}
	})

	t.Run("empty control namespace is clean", func(t *testing.T) {
		rootPath := t.TempDir()
		root, _, err := openRepository(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
			root.Close()
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		inspection, err := InspectControlState(context.Background(), rootPath)
		assertControlInspection(t, inspection, err, ControlStateClean, "")
	})

	for _, terminalState := range []string{StateApplied, StateRolledBack} {
		t.Run("valid terminal "+terminalState+" is clean", func(t *testing.T) {
			rootPath := t.TempDir()
			plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			if terminalState == StateApplied {
				if result, err := Apply(context.Background(), rootPath, plan); err != nil || result.State != StateApplied {
					t.Fatalf("Apply()=%#v, %v", result, err)
				}
			} else {
				leaveInterruptedPrefix(t, rootPath, plan, 0)
				if result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryRollback); err != nil || result.State != StateRolledBack {
					t.Fatalf("Recover()=%#v, %v", result, err)
				}
			}
			inspection, err := InspectControlState(context.Background(), rootPath)
			assertControlInspection(t, inspection, err, ControlStateClean, "")
		})
	}

	t.Run("active canonical journal is recoverable", func(t *testing.T) {
		rootPath := t.TempDir()
		plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
		if err != nil {
			t.Fatal(err)
		}
		leaveInterruptedPrefix(t, rootPath, plan, 0)
		inspection, err := InspectControlState(context.Background(), rootPath)
		assertControlInspection(t, inspection, err, ControlStateRecoverable, plan.TransactionID)
	})

	t.Run("canonical preparing journal is recoverable", func(t *testing.T) {
		rootPath := t.TempDir()
		plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
		if err != nil {
			t.Fatal(err)
		}
		root, _, err := openRepository(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
			root.Close()
			t.Fatal(err)
		}
		content, err := stablejson.Marshal(journalValue(plan))
		if err != nil {
			root.Close()
			t.Fatal(err)
		}
		if err := writeOwnedFile(root, journalTemp, content, 0o600); err != nil {
			root.Close()
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		inspection, err := InspectControlState(context.Background(), rootPath)
		assertControlInspection(t, inspection, err, ControlStateRecoverable, plan.TransactionID)
	})
}

func TestControlInspectionOnlyPromotesOperationalCleanupFailures(t *testing.T) {
	cleanupErr := closeReadResource(errorCloser{}, "test resource")
	if !errors.Is(cleanupErr, ErrReadCleanup) || !errors.Is(controlInspectionOperationalError(cleanupErr), ErrReadCleanup) {
		t.Fatalf("cleanup error=%v promoted=%v", cleanupErr, controlInspectionOperationalError(cleanupErr))
	}
	if promoted := controlInspectionOperationalError(errors.New("malformed caller state")); promoted != nil {
		t.Fatalf("semantic admission error promoted as operational: %v", promoted)
	}
}

type errorCloser struct{}

func (errorCloser) Close() error {
	return errors.New("injected close failure")
}

func TestInspectControlStateRejectsMalformedAndConflictingState(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "malformed journal has unknown identity", setup: setupMalformedInspectionJournal},
		{name: "conflicting terminal routes", setup: setupConflictingInspectionTerminals},
		{name: "conflicting terminal markers", setup: setupConflictingInspectionMarkers},
		{name: "malformed terminal receipt", setup: setupMalformedInspectionTerminalReceipt},
		{name: "unknown caller-named control entry", setup: setupUnknownInspectionEntry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			test.setup(t, rootPath)
			inspection, err := InspectControlState(context.Background(), rootPath)
			assertControlInspection(t, inspection, err, ControlStateInvalid, "")
			if strings.Contains(fmt.Sprintf("%#v", inspection), "caller-private-label") {
				t.Fatal("control inspection disclosed a caller-owned entry name")
			}
		})
	}
}

func setupMalformedInspectionJournal(t *testing.T, rootPath string) {
	t.Helper()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, journalTemp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setupConflictingInspectionTerminals(t *testing.T, rootPath string) {
	t.Helper()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, digit := range []string{"1", "2"} {
		transactionID := "sha256:" + strings.Repeat(digit, 64)
		if err := root.Mkdir(filepath.FromSlash(terminalTombstonePath(transactionID, StateApplied)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func setupConflictingInspectionMarkers(t *testing.T, rootPath string) {
	t.Helper()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeMarker(root, committedMarker); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(root, rolledBackMarker); err != nil {
		t.Fatal(err)
	}
}

func setupMalformedInspectionTerminalReceipt(t *testing.T, rootPath string) {
	t.Helper()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, plan); err != nil || result.State != StateApplied {
		t.Fatalf("Apply()=%#v, %v", result, err)
	}
	path := filepath.Join(rootPath, filepath.FromSlash(terminalTombstonePath(plan.TransactionID, StateApplied)), terminalReceiptName)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setupUnknownInspectionEntry(t *testing.T, rootPath string) {
	t.Helper()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, ControlDirectory+"/caller-private-label", []byte("opaque"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInspectControlStateReturnsBusyAndRespectsContext(t *testing.T) {
	rootPath := t.TempDir()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := acquireTransactionLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	if _, err := InspectControlState(context.Background(), rootPath); !errors.Is(err, ErrBusy) {
		t.Fatalf("InspectControlState() error=%v, want ErrBusy", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectControlState(cancelled, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("InspectControlState(cancelled) error=%v, want context.Canceled", err)
	}
}

func TestInspectionLeasePinsRootAndExcludesCooperativeWriter(t *testing.T) {
	rootPath := t.TempDir()
	initial, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, initial); err != nil || result.State != StateApplied {
		t.Fatalf("initial Apply()=%#v, %v", result, err)
	}
	next, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/b.json", Content: []byte("b\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if inspection, err := lease.InspectControlState(context.Background()); err != nil || inspection.State != ControlStateClean {
		lease.Close()
		t.Fatalf("lease inspection=%#v, %v", inspection, err)
	}
	if _, err := Apply(context.Background(), rootPath, next); !errors.Is(err, ErrBusy) {
		lease.Close()
		t.Fatalf("Apply() while inspection lease held error=%v, want ErrBusy", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, next); err != nil || result.State != StateApplied {
		t.Fatalf("Apply() after inspection lease=%#v, %v", result, err)
	}
}

func TestInspectionLeaseDoesNotResolveAReplacementRoot(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	lease, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	savedPath := rootPath + "-saved"
	replacementPath := rootPath + "-replacement"
	if err := os.Mkdir(replacementPath, 0o755); err != nil {
		lease.Close()
		t.Fatal(err)
	}
	setupUnknownInspectionEntry(t, replacementPath)
	if err := os.Rename(rootPath, savedPath); err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, rootPath); err != nil {
		lease.Close()
		t.Fatal(err)
	}

	inspection, inspectErr := lease.InspectControlState(context.Background())
	if inspectErr != nil || inspection.State != ControlStateClean {
		lease.Close()
		t.Fatalf("pinned inspection=%#v, %v, want original clean root", inspection, inspectErr)
	}
	if err := lease.VerifyRootIdentity(); !errors.Is(err, ErrControlStateChanged) {
		lease.Close()
		t.Fatalf("VerifyRootIdentity() error=%v, want ErrControlStateChanged", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectionLeaseRejectsControlNamespaceCreatedAfterOpen(t *testing.T) {
	rootPath := t.TempDir()
	lease, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootPath, filepath.FromSlash(ControlDirectory)), 0o700); err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if inspection, err := lease.InspectControlState(context.Background()); !errors.Is(err, ErrControlStateChanged) || inspection != (ControlInspection{}) {
		lease.Close()
		t.Fatalf("InspectControlState()=%#v, %v, want control-state change", inspection, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectControlFileRejectsGrowthAfterRoutePreflight(t *testing.T) {
	rootPath := t.TempDir()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	const relativePath = activeDirectory + "/growth.bin"
	if err := writeOwnedFile(root, relativePath, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat(filepath.FromSlash(relativePath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, filepath.FromSlash(relativePath)), bytes.Repeat([]byte{'b'}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectControlFileDigest(context.Background(), root, relativePath, before, 16); !errors.Is(err, ErrControlStateChanged) {
		t.Fatalf("inspectControlFileDigest() error = %v, want ErrControlStateChanged", err)
	}
}

func TestInspectControlFileRejectsSameByteRouteReplacement(t *testing.T) {
	rootPath := t.TempDir()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	const relativePath = activeDirectory + "/record.json"
	content := []byte("same bytes\n")
	if err := writeOwnedFile(root, relativePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat(filepath.FromSlash(relativePath))
	if err != nil {
		t.Fatal(err)
	}
	_, err = inspectControlFileDigestWithHook(context.Background(), root, relativePath, before, MaximumFileBytes, func() {
		if renameErr := root.Rename(filepath.FromSlash(relativePath), filepath.FromSlash(relativePath+".original")); renameErr != nil {
			t.Fatal(renameErr)
		}
		if writeErr := writeOwnedFile(root, relativePath, content, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if !errors.Is(err, ErrControlStateChanged) {
		t.Fatalf("inspectControlFileDigestWithHook() error=%v, want control-state change", err)
	}
}

func TestInspectionLeaseExportsOnlyReadOnlyFileCapability(t *testing.T) {
	leaseType := reflect.TypeOf((*InspectionLease)(nil))
	if _, exists := leaseType.MethodByName("Root"); exists {
		t.Fatal("InspectionLease exports its mutation-capable confined root")
	}
	osRootType := reflect.TypeOf((*os.Root)(nil))
	for index := 0; index < leaseType.NumMethod(); index++ {
		method := leaseType.Method(index)
		for output := 0; output < method.Type.NumOut(); output++ {
			if method.Type.Out(output) == osRootType {
				t.Fatalf("InspectionLease.%s exports *os.Root", method.Name)
			}
		}
	}
}

func TestInspectionLeaseFileCannotBeReassertedAsMutable(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "record.json"), []byte("record\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lease, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := lease.OpenExactRegularFile("record.json")
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	type byteWriter interface {
		Write([]byte) (int, error)
	}
	if _, mutable := file.(byteWriter); mutable {
		file.Close()
		lease.Close()
		t.Fatal("inspection file exposes a mutation method through its dynamic type")
	}
	if _, rawFile := file.(*os.File); rawFile {
		file.Close()
		lease.Close()
		t.Fatal("inspection file exposes its mutation-capable operating-system descriptor")
	}
	if err := file.Close(); err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectControlStateEpochIsDeterministicAndContentBound(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		root.Close()
		t.Fatal(err)
	}
	content, err := stablejson.Marshal(journalValue(plan))
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, journalTemp, content, 0o600); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}

	first, err := InspectControlState(context.Background(), rootPath)
	assertControlInspection(t, first, err, ControlStateRecoverable, plan.TransactionID)
	second, err := InspectControlState(context.Background(), rootPath)
	assertControlInspection(t, second, err, ControlStateRecoverable, plan.TransactionID)
	if first != second {
		t.Fatalf("deterministic inspection changed: first=%#v second=%#v", first, second)
	}

	root, _, err = openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(filepath.FromSlash(journalTemp), filepath.FromSlash(journalPath)); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := InspectControlState(context.Background(), rootPath)
	assertControlInspection(t, third, err, ControlStateRecoverable, plan.TransactionID)
	if third.EpochID == first.EpochID {
		t.Fatal("control epoch did not change when admitted control content changed")
	}
}

func TestInspectControlStateRejectsPartialControlObservations(t *testing.T) {
	t.Run("entry overflow", func(t *testing.T) {
		rootPath := t.TempDir()
		root, _, err := openRepository(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
			root.Close()
			t.Fatal(err)
		}
		for index := 0; index < 4; index++ {
			if err := writeOwnedFile(root, fmt.Sprintf("%s/unknown-%d", ControlDirectory, index), []byte("opaque"), 0o600); err != nil {
				root.Close()
				t.Fatal(err)
			}
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}

		inspection, err := InspectControlState(context.Background(), rootPath)
		if !errors.Is(err, errControlObservationBound) || inspection != (ControlInspection{}) {
			t.Fatalf("InspectControlState()=%#v, %v, want bounded failure", inspection, err)
		}
	})

	t.Run("nested directory", func(t *testing.T) {
		rootPath := t.TempDir()
		root, _, err := openRepository(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := ensureDirectory(root, activeDirectory+"/nested", 0o700); err != nil {
			root.Close()
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}

		inspection, err := InspectControlState(context.Background(), rootPath)
		if !errors.Is(err, errControlObservationShape) || inspection != (ControlInspection{}) {
			t.Fatalf("InspectControlState()=%#v, %v, want unsupported-shape failure", inspection, err)
		}
	})
}

func TestInspectControlStateHashesSymlinkTargetsWithoutDisclosingThem(t *testing.T) {
	rootPath := t.TempDir()
	controlPath := filepath.Join(rootPath, filepath.FromSlash(ControlDirectory))
	if err := os.MkdirAll(controlPath, 0o700); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(controlPath, "unknown")
	if err := os.Symlink("alpha", linkPath); err != nil {
		t.Fatal(err)
	}
	first, err := InspectControlState(context.Background(), rootPath)
	assertControlInspection(t, first, err, ControlStateInvalid, "")

	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("omega", linkPath); err != nil {
		t.Fatal(err)
	}
	second, err := InspectControlState(context.Background(), rootPath)
	assertControlInspection(t, second, err, ControlStateInvalid, "")
	if first.EpochID == second.EpochID {
		t.Fatal("same-length symlink target change did not change the control epoch")
	}
	if strings.Contains(fmt.Sprintf("%#v %#v", first, second), "alpha") || strings.Contains(fmt.Sprintf("%#v %#v", first, second), "omega") {
		t.Fatal("control inspection disclosed a symlink target")
	}
}

func TestInspectControlStateUsesPortableObservationFields(t *testing.T) {
	rootPath := t.TempDir()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	const directoryName = "unknown"
	const fileName = "payload"
	directoryPath := ControlDirectory + "/" + directoryName
	if err := ensureDirectory(root, directoryPath, 0o700); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, directoryPath+"/"+fileName, []byte("alpha"), 0o600); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}

	observationID, err := digest.StableJSONSHA256Ref(map[string]any{
		"controlObservationKind": "proofkit.repository-control-observation",
		"entries": []any{map[string]any{
			"entries": []any{map[string]any{
				"contentId": digest.SHA256TextRef("alpha"),
				"kind":      "regular",
				"mode":      json.Number("384"),
				"nameId":    digest.SHA256TextRef(fileName),
				"size":      json.Number("5"),
			}},
			"kind":   "directory",
			"mode":   json.Number("448"),
			"nameId": digest.SHA256TextRef(directoryName),
		}},
		"schemaVersion": json.Number("1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := newControlInspection(ControlStateInvalid, "", observationID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectControlState(context.Background(), rootPath)
	if err != nil || got != want {
		t.Fatalf("InspectControlState()=%#v, %v, want %#v", got, err, want)
	}
}

func TestInspectControlStateNormalizesPortableEntryNames(t *testing.T) {
	for _, pair := range [][2]string{
		{"caf\u00e9", "cafe\u0301"},
		{"Custom", "custom"},
	} {
		left := invalidControlEpochForNames(t, pair[0])
		right := invalidControlEpochForNames(t, pair[1])
		if left != right {
			t.Fatalf("portable-equivalent names %q and %q produced different epochs", pair[0], pair[1])
		}
	}
	var expectedEpoch string
	for _, names := range [][3]string{
		{"a", "Z", "caf\u00e9"},
		{"A", "z", "cafe\u0301"},
		{"a", "z", "caf\u00e9"},
	} {
		for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
			permuted := []string{names[order[0]], names[order[1]], names[order[2]]}
			entries := []fs.DirEntry{testNamedDirEntry(permuted[0]), testNamedDirEntry(permuted[1]), testNamedDirEntry(permuted[2])}
			if err := sortInspectionEntries(entries); err != nil {
				t.Fatal(err)
			}
			gotOrder := []string{entries[0].Name(), entries[1].Name(), entries[2].Name()}
			wantOrder := []string{names[0], names[2], names[1]}
			if !reflect.DeepEqual(gotOrder, wantOrder) {
				t.Fatalf("portable entry order=%q, want %q", gotOrder, wantOrder)
			}
			epoch := invalidControlEpochForNames(t, permuted...)
			if expectedEpoch == "" {
				expectedEpoch = epoch
			} else if epoch != expectedEpoch {
				t.Fatalf("portable-equivalent entry set %q changed epoch", permuted)
			}
		}
	}
}

func TestInspectControlStateRejectsClassificationChangeHiddenByPortableNameIdentity(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	lease, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	_, err = lease.inspectControlState(context.Background(), func() {
		from := filepath.Join(rootPath, filepath.FromSlash(activeDirectory))
		to := filepath.Join(rootPath, filepath.FromSlash(ControlDirectory), "ACTIVE")
		if renameErr := os.Rename(from, to); renameErr != nil {
			t.Fatal(renameErr)
		}
	})
	if !errors.Is(err, ErrControlStateChanged) {
		t.Fatalf("InspectControlState() error=%v, want control-state change", err)
	}
}

func TestControlObservationRejectsPortableEntryAliasCollision(t *testing.T) {
	for _, pair := range [][2]string{{"caf\u00e9", "cafe\u0301"}, {"Z", "z"}, {"same", "same"}} {
		for _, order := range [][2]int{{0, 1}, {1, 0}} {
			entries := []fs.DirEntry{testNamedDirEntry(pair[order[0]]), testNamedDirEntry(pair[order[1]])}
			if err := sortInspectionEntries(entries); !errors.Is(err, errControlObservationShape) {
				t.Fatalf("sortInspectionEntries() error=%v, want unsupported shape", err)
			}
		}
	}
}

func invalidControlEpochForNames(t *testing.T, names ...string) string {
	t.Helper()
	rootPath := t.TempDir()
	controlPath := filepath.Join(rootPath, filepath.FromSlash(ControlDirectory))
	if err := os.MkdirAll(controlPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(controlPath, name), []byte("portable\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspection, err := InspectControlState(context.Background(), rootPath)
	if err != nil || inspection.State != ControlStateInvalid {
		t.Fatalf("InspectControlState()=%#v, %v, want invalid", inspection, err)
	}
	return inspection.EpochID
}

type testNamedDirEntry string

func (entry testNamedDirEntry) Name() string         { return string(entry) }
func (testNamedDirEntry) IsDir() bool                { return false }
func (testNamedDirEntry) Type() fs.FileMode          { return 0 }
func (testNamedDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestInspectControlStateDoesNotMutateExistingNamespace(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	before := snapshotTestTree(t, rootPath)
	inspection, err := InspectControlState(context.Background(), rootPath)
	assertControlInspection(t, inspection, err, ControlStateRecoverable, plan.TransactionID)
	after := snapshotTestTree(t, rootPath)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only inspection mutated repository:\nbefore=%#v\nafter=%#v", before, after)
	}
}

type testTreeEntry struct {
	Content []byte
	Mode    fs.FileMode
	Path    string
}

func snapshotTestTree(t *testing.T, rootPath string) []testTreeEntry {
	t.Helper()
	entries := []testTreeEntry{}
	err := filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == rootPath {
			return nil
		}
		relative, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := testTreeEntry{Mode: info.Mode(), Path: filepath.ToSlash(relative)}
		if info.Mode().IsRegular() {
			item.Content, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		entries = append(entries, item)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	for index := range entries {
		entries[index].Content = bytes.Clone(entries[index].Content)
	}
	return entries
}

func assertControlInspection(t *testing.T, got ControlInspection, err error, state, transactionID string) {
	t.Helper()
	if err != nil {
		t.Fatalf("InspectControlState() error=%v", err)
	}
	if got.State != state || got.TransactionID != transactionID {
		t.Fatalf("InspectControlState()=%#v, want state=%q transactionId=%q", got, state, transactionID)
	}
	if !strings.HasPrefix(got.EpochID, "sha256:") || len(got.EpochID) != len("sha256:")+64 {
		t.Fatalf("InspectControlState() epochId=%q", got.EpochID)
	}
}
