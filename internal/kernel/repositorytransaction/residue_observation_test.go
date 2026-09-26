package repositorytransaction

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestPreparationResidueExactTokenReference(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, []byte("partial bytes"))
	terminalName := "retired-gc-" + strings.Repeat("1", 64) + "-applied"
	terminalPath := ControlDirectory + "/" + terminalName
	if err := os.Mkdir(filepath.Join(root, terminalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// The oracle is independently assembled from filesystem operands, not a
	// production observation builder or the portable ControlInspection epoch.
	node := func(name, label, kind string, mode int64) map[string]any {
		t.Helper()
		info := residueStat(t, root, name)
		identity, err := platformFileIdentity(info)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"name": label, "kind": kind, "identity": identity,
			"mode":    json.Number(strconv.FormatInt(mode, 10)),
			"ownerId": json.Number(strconv.Itoa(os.Geteuid())),
		}
	}
	rootIdentity, err := platformFileIdentity(residueStat(t, root, "."))
	if err != nil {
		t.Fatal(err)
	}
	active := node(activeDirectory, "active", "directory", int64(os.ModeDir|0o700))
	journal := node(journalTemp, "journal.tmp", "regular", 0o600)
	journal["size"] = json.Number("13")
	journal["contentId"] = digest.SHA256TextRef("partial bytes")
	active["journal"] = journal
	terminal := node(terminalPath, terminalName, "directory", int64(os.ModeDir|0o700))
	terminal["receipt"] = nil
	reference := map[string]any{
		"observationKind": "proofkit.preparation-residue-observation", "schemaVersion": json.Number("1"),
		"rootId":          digest.SHA256TextRef(filepath.Clean(root) + "\x00" + rootIdentity),
		"effectiveUserId": json.Number(strconv.Itoa(os.Geteuid())),
		ControlRoot:       node(ControlRoot, ".agentic-proofkit", "directory", int64(os.ModeDir|0o700)),
		ControlDirectory:  node(ControlDirectory, "transactions", "directory", int64(os.ModeDir|0o700)),
		"active":          active, "terminal": terminal,
	}
	want, err := digest.StableJSONSHA256Ref(reference)
	if err != nil {
		t.Fatal(err)
	}
	got := residueObservation(t, root)
	if got.ObservationID != want {
		t.Fatal("native token does not bind the independently enumerated exact operands")
	}
	for _, operand := range []string{"observationKind", "schemaVersion", "rootId", "effectiveUserId", ControlRoot, ControlDirectory, "active", "terminal"} {
		original := reference[operand]
		delete(reference, operand)
		weakened, err := digest.StableJSONSHA256Ref(reference)
		if err != nil || weakened == got.ObservationID {
			t.Fatalf("missing top-level operand: %s", operand)
		}
		reference[operand] = original
	}
}

func TestPreparationResidueStableReadRejectsIntervalChanges(t *testing.T) {
	for _, scenario := range []string{"content", "mode", "inode", "size"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, []byte("partial"))
			before := residueStat(t, root, journalTemp)
			fired := false
			operations := nativeResidueOperations()
			operations.openFile = func(lease *InspectionLease, name string) (InspectionFile, error) {
				file, err := lease.OpenExactRegularFile(name)
				if err != nil {
					return nil, err
				}
				return residueFaultFile{InspectionFile: file, afterRead: func() {
					if fired {
						return
					}
					fired = true
					switch scenario {
					case "content":
						mustWriteTestFile(t, root, journalTemp, "changed", 0o600)
						later := before.ModTime().Add(time.Second)
						if err := os.Chtimes(filepath.Join(root, journalTemp), later, later); err != nil {
							t.Fatal(err)
						}
					case "mode":
						if err := os.Chmod(filepath.Join(root, journalTemp), 0o640); err != nil {
							t.Fatal(err)
						}
					case "inode":
						if err := os.Rename(filepath.Join(root, journalTemp), filepath.Join(root, "saved")); err != nil {
							t.Fatal(err)
						}
						mustWriteTestFile(t, root, journalTemp, "partial", 0o600)
					case "size":
						mustWriteTestFile(t, root, journalTemp, "longer", 0o600)
					}
				}}, nil
			}
			got, err := inspectPreparationResidue(context.Background(), root, operations)
			residueAssertError(t, err, ErrControlStateChanged)
			if got != (PreparationResidueObservation{}) || !fired {
				t.Fatal("changed read produced eligibility or missed its barrier")
			}
		})
	}
}

func TestPreparationResidueCleanTerminalOwnerParity(t *testing.T) {
	for _, scenario := range []string{"retired-empty", "retired-receipt", "retained-receipt", "empty-retained", "bad-receipt", "uncompacted"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			residueFixture(t, root, nil)
			id := digest.SHA256TextRef("old terminal")
			name := terminalTombstonePath(id, StateApplied)
			if strings.HasPrefix(scenario, "retired-") {
				name = retiredTerminalTombstonePath(id, StateApplied)
			}
			if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
				t.Fatal(err)
			}
			if scenario != "retired-empty" && scenario != "empty-retained" {
				content, err := stablejson.Marshal(terminalReceiptValue(terminalReceipt{TransactionID: id, State: StateApplied, AppliedCount: 1}))
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "bad-receipt" {
					content = []byte("{private-invalid-receipt")
				}
				mustWriteTestFile(t, root, name+"/"+terminalReceiptName, string(content), 0o600)
			}
			if scenario == "uncompacted" {
				mustWriteTestFile(t, root, name+"/journal.tmp", "partial", 0o600)
			}
			lease, err := OpenInspectionLease(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := controlEntries(lease.root)
			if err != nil {
				t.Fatal(err)
			}
			terminal, found, err := findTerminalControlEntry(entries)
			if err != nil || !found {
				t.Fatal("terminal route fixture")
			}
			state, ownerErr := terminalControlState(lease.root, terminal)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := InspectPreparationResidue(context.Background(), root)
			if ownerErr == nil && state == ControlStateClean {
				if err != nil || got.State != PreparationResidueEligible {
					t.Fatalf("clean owner rejected: %#v %v", got, err)
				}
			} else {
				residueAssertError(t, err, ErrResidueIneligible)
				if got != (PreparationResidueObservation{}) || strings.Contains(err.Error(), "private-invalid") {
					t.Fatal("invalid owner admitted or leaked")
				}
			}
		})
	}
}

func TestPreparationResidueTerminalReadFailureAndCancellation(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, nil)
	id := digest.SHA256TextRef("terminal")
	name := terminalTombstonePath(id, StateApplied)
	if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := stablejson.Marshal(terminalReceiptValue(terminalReceipt{State: StateApplied, TransactionID: id, AppliedCount: 1}))
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, root, name+"/"+terminalReceiptName, string(content), 0o600)
	residueObservation(t, root)
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		operations := nativeResidueOperations()
		reads := 0
		operations.openFile = func(*InspectionLease, string) (InspectionFile, error) {
			reads++
			if canceled {
				cancel()
			}
			return nil, errors.New("untrusted operational text")
		}
		before := residueTree(t, root)
		got, err := inspectPreparationResidue(ctx, root, operations)
		cancel()
		if reads != 1 || got != (PreparationResidueObservation{}) || !errors.Is(err, ErrResidueOperation) || errors.Is(err, context.Canceled) != canceled || errors.Is(err, ErrResidueIneligible) || strings.Contains(err.Error(), "untrusted") {
			t.Fatalf("terminal operation reclassified: %#v %v", got, err)
		}
		if !reflect.DeepEqual(before, residueTree(t, root)) {
			t.Fatal("terminal read failure changed evidence")
		}
	}
}

func TestPreparationResiduePinsParentThroughFinalReadback(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, []byte("retained"))
	observation := residueObservation(t, root)
	destination := residueDestination(observation.ObservationID)
	operations := nativeResidueOperations()
	moved, replaced := false, false
	operations.barrier = func(point string) error {
		if point == "published" {
			moved = true
		}
		return nil
	}
	operations.openFile = func(lease *InspectionLease, name string) (InspectionFile, error) {
		file, err := lease.OpenExactRegularFile(name)
		if err != nil {
			return nil, err
		}
		if !moved || replaced {
			return file, nil
		}
		return residueFaultFile{InspectionFile: file, afterRead: func() {
			if replaced {
				return
			}
			replaced = true
			parent := filepath.Join(root, preparationResidueDirectory)
			if err := os.Rename(parent, parent+"-saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(parent+"-saved", filepath.Base(destination)), filepath.Join(root, destination)); err != nil {
				t.Fatal(err)
			}
		}}, nil
	}
	got, err := quarantinePreparationResidue(context.Background(), root, observation.ObservationID, operations)
	if !replaced || got != (PreparationResidueRelocation{}) || !errors.Is(err, ErrResidueOutcomeUnverified) || !errors.Is(err, ErrControlStateChanged) {
		t.Fatalf("replaced parent survived final readback: %#v %v", got, err)
	}
	assertTestFile(t, root, destination+"/journal.tmp", "retained", 0o600)
}
