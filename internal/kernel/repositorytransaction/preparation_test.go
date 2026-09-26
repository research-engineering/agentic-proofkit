package repositorytransaction

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const testResidueDirectory = ControlRoot + "/transaction-residue"

// Existing recovery fixtures use the production transition under its writer lock.
func prepareJournal(root *os.Root, plan Plan) error {
	if err := validateActivePlan(plan); err != nil {
		return err
	}
	lock, err := acquireTransactionLock(root)
	if err != nil {
		return err
	}
	defer lock.release()
	_, err = (engine{}).prepareJournal(context.Background(), root, lock, plan)
	return err
}

func preparationTargets() []Target {
	return []Target{
		{Path: "existing", Content: []byte("after"), Mode: 0o644},
		{Path: "deleted", Absent: true},
		{Path: "new/target", Content: []byte("created"), Mode: 0o644},
	}
}

func preparationFixture(t *testing.T) (string, Plan, string, []testTreeEntry) {
	t.Helper()
	rootPath := t.TempDir()
	prior, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "prior", Content: []byte("prior"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, prior); err != nil || result.State != StateApplied {
		t.Fatalf("prior terminal: %#v %v", result, err)
	}
	terminalPath := filepath.Join(rootPath, terminalTombstonePath(prior.TransactionID, StateApplied))
	terminal := snapshotTestTree(t, terminalPath)
	mustWriteTestFile(t, rootPath, "existing", "before", 0o600)
	mustWriteTestFile(t, rootPath, "deleted", "delete-before", 0o640)
	plan, err := BuildPlan(context.Background(), rootPath, preparationTargets())
	if err != nil {
		t.Fatal(err)
	}
	return rootPath, plan, terminalPath, terminal
}

func assertPreparationBeforeState(t *testing.T, rootPath, terminalPath string, terminal []testTreeEntry) {
	t.Helper()
	assertTestFile(t, rootPath, "existing", "before", 0o600)
	assertTestFile(t, rootPath, "deleted", "delete-before", 0o640)
	assertTestFile(t, rootPath, "prior", "prior", 0o600)
	if _, err := os.Lstat(filepath.Join(rootPath, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preparation created target parent: %v", err)
	}
	if got := snapshotTestTree(t, terminalPath); !reflect.DeepEqual(got, terminal) {
		t.Fatalf("prior terminal changed: %#v", got)
	}
}

func TestPreparationProcessDeath(t *testing.T) {
	if boundary := os.Getenv("PROOFKIT_PREPARATION_BOUNDARY"); boundary != "" {
		rootPath := os.Getenv("PROOFKIT_PREPARATION_ROOT")
		plan, err := BuildPlan(context.Background(), rootPath, preparationTargets())
		if err != nil {
			t.Fatal(err)
		}
		runtime := engine{fault: func(point failurePoint, _ int) error {
			if string(point) == boundary {
				fmt.Fprintln(os.Stdout, boundary)
				os.Exit(73)
			}
			return nil
		}}
		_, _ = runtime.apply(context.Background(), rootPath, plan)
		os.Exit(74) // A missing hook is not evidence of process death at the boundary.
	}
	for _, boundary := range []string{
		"before_preparation_mkdir", "after_residue_parent", "after_preparation_mkdir",
		"after_preparation_file_create", "after_preparation_partial_write",
		"after_preparation_full_write", "after_preparation_file_sync",
		"after_preparation_journal", "before_preparation_publish", "after_preparation_publish",
	} {
		t.Run(boundary, func(t *testing.T) {
			rootPath, plan, terminalPath, terminal := preparationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPreparationProcessDeath$")
			command.Env = append(os.Environ(), "PROOFKIT_PREPARATION_BOUNDARY="+boundary, "PROOFKIT_PREPARATION_ROOT="+rootPath)
			// CombinedOutput owns Start/Wait and reaps even a watchdog-killed child.
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exitError) || exitError.ExitCode() != 73 || string(output) != boundary+"\n" {
				t.Fatalf("boundary not reached: output=%q error=%v watchdog=%v", output, err, ctx.Err())
			}
			assertPreparationBeforeState(t, rootPath, terminalPath, terminal)
			published := boundary == "after_preparation_publish"
			canonical, err := stablejson.Marshal(journalValue(plan))
			if err != nil {
				t.Fatal(err)
			}
			residues := preparationResidues(t, rootPath)
			if published {
				if len(residues) != 0 {
					t.Fatal("published preparation also retained in residue")
				}
				assertTestFile(t, rootPath, journalPath, string(canonical), 0o600)
			} else {
				assertNoActiveTransaction(t, rootPath)
				wantResidues := 1
				if boundary == "before_preparation_mkdir" || boundary == "after_residue_parent" {
					wantResidues = 0
				}
				if len(residues) != wantResidues {
					t.Fatalf("retained residues=%d want=%d", len(residues), wantResidues)
				}
				if len(residues) == 1 {
					assertPreparationResidue(t, rootPath, residues[0], boundary, canonical)
				}
			}
			beforeRestart := snapshotTestTree(t, rootPath)
			planned, err := BuildPlan(context.Background(), rootPath, preparationTargets())
			if !published {
				if err != nil || planned.TransactionID != plan.TransactionID {
					t.Fatalf("unpublished residue blocks planning: %#v %v", planned, err)
				}
			} else {
				var required *RecoveryRequiredError
				if !errors.As(err, &required) || required.TransactionID != plan.TransactionID {
					t.Fatalf("published journal lost identity: %v", err)
				}
			}
			resume, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
			if published && (err != nil || resume.State != StateRecoveryRequired || resume.TransactionID != plan.TransactionID) {
				t.Fatalf("unready journal resumed: %#v %v", resume, err)
			}
			if !published && err == nil && resume.State != StateRecoveryRequired {
				t.Fatalf("unpublished residue admitted as recovery: %#v", resume)
			}
			if !reflect.DeepEqual(beforeRestart, snapshotTestTree(t, rootPath)) {
				t.Fatal("planning or refused recovery consumed preparation evidence")
			}
			if published {
				rolledBack, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryRollback)
				if err != nil || rolledBack.State != StateRolledBack || rolledBack.TransactionID != plan.TransactionID || !rolledBack.AppliedCountKnown || rolledBack.AppliedCount != 0 {
					t.Fatalf("published preparing rollback: %#v %v", rolledBack, err)
				}
				assertNoActiveTransaction(t, rootPath)
			}
		})
	}
}

func preparationResidues(t *testing.T, rootPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(rootPath, testResidueDirectory))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, entry := range entries {
		paths = append(paths, testResidueDirectory+"/"+entry.Name())
	}
	return paths
}

func assertPreparationResidue(t *testing.T, rootPath, residue, boundary string, canonical []byte) {
	t.Helper()
	info, err := os.Lstat(filepath.Join(rootPath, residue))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("unsafe residue: %v", err)
	}
	entries := snapshotTestTree(t, filepath.Join(rootPath, residue))
	if boundary == "after_preparation_mkdir" {
		if len(entries) != 0 {
			t.Fatal("empty preparation contains files")
		}
		return
	}
	name, content := "journal.tmp", canonical
	switch boundary {
	case "after_preparation_file_create":
		content = nil
	case "after_preparation_partial_write":
		content = canonical[:len(canonical)/2]
	case "after_preparation_journal", "before_preparation_publish":
		name = "journal.json"
	}
	if len(entries) != 1 || entries[0].Path != name || entries[0].Mode != 0o600 || !bytes.Equal(entries[0].Content, content) {
		t.Fatalf("wrong retained prefix at %s: %#v", boundary, entries)
	}
}

func TestPreparationRejectsExistingActive(t *testing.T) {
	rootPath, plan, _, _ := preparationFixture(t)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	before := snapshotTestTree(t, filepath.Join(rootPath, activeDirectory))
	if err := prepareJournal(root, plan); err == nil {
		t.Fatal("preparation admitted an existing empty active directory")
	}
	if !reflect.DeepEqual(before, snapshotTestTree(t, filepath.Join(rootPath, activeDirectory))) {
		t.Fatal("existing active was changed")
	}
}

func TestPreparationErrorsPreserveEvidence(t *testing.T) {
	for _, boundary := range []failurePoint{
		faultBeforePreparationMkdir, faultAfterResidueParent, faultAfterPreparationMkdir,
		faultAfterPreparationFileCreate, faultAfterPreparationPartialWrite, faultAfterPreparationFullWrite,
		faultAfterPreparationFileSync, faultAfterPreparationJournal, faultBeforePreparationPublish,
		faultAfterPreparationPublish,
	} {
		t.Run(string(boundary), func(t *testing.T) {
			rootPath, plan, terminalPath, terminal := preparationFixture(t)
			sentinel := errors.New("preparation fault")
			reached := false
			runtime := engine{fault: func(point failurePoint, _ int) error {
				if point == boundary {
					reached = true
					return sentinel
				}
				return nil
			}}
			result, err := runtime.apply(context.Background(), rootPath, plan)
			if !reached {
				t.Fatal("fault boundary was not reached")
			}
			assertPreparationBeforeState(t, rootPath, terminalPath, terminal)
			if boundary == faultAfterPreparationPublish {
				if err != nil || result.State != StateRecoveryRequired || result.TransactionID != plan.TransactionID || result.AppliedCountKnown || result.AppliedCount != 0 {
					t.Fatalf("post-publication failure: %#v %v", result, err)
				}
				assertPublishedPreparation(t, rootPath, plan)
				return
			}
			if !errors.Is(err, sentinel) || result != (Result{}) {
				t.Fatalf("pre-publication failure produced result: %#v %v", result, err)
			}
			assertNoActiveTransaction(t, rootPath)
			residues := preparationResidues(t, rootPath)
			if boundary != faultBeforePreparationMkdir && boundary != faultAfterResidueParent {
				if len(residues) != 1 {
					t.Fatalf("lost preparation evidence: %v", residues)
				}
				canonical, err := stablejson.Marshal(journalValue(plan))
				if err != nil {
					t.Fatal(err)
				}
				assertPreparationResidue(t, rootPath, residues[0], string(boundary), canonical)
			}
			before := snapshotTestTree(t, rootPath)
			if _, err := BuildPlan(context.Background(), rootPath, preparationTargets()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, snapshotTestTree(t, rootPath)) {
				t.Fatal("restart changed retained preparation evidence")
			}
		})
	}
}

func assertPublishedPreparation(t *testing.T, rootPath string, plan Plan) {
	t.Helper()
	canonical, err := stablejson.Marshal(journalValue(plan))
	if err != nil {
		t.Fatal(err)
	}
	entries := snapshotTestTree(t, filepath.Join(rootPath, activeDirectory))
	if len(entries) != 1 || entries[0].Path != "journal.json" || !bytes.Equal(entries[0].Content, canonical) || entries[0].Mode != 0o600 {
		t.Fatalf("published journal lost or unready state changed: %#v", entries)
	}
	var required *RecoveryRequiredError
	if _, err := BuildPlan(context.Background(), rootPath, preparationTargets()); !errors.As(err, &required) || required.TransactionID != plan.TransactionID {
		t.Fatalf("public planning lost published identity: %v", err)
	}
}

func TestPreparationParentSyncErrorsRetainPublishedIdentity(t *testing.T) {
	for _, failedParent := range []string{testResidueDirectory, ControlDirectory} {
		t.Run(failedParent, func(t *testing.T) {
			rootPath, plan, terminalPath, terminal := preparationFixture(t)
			var synced []string
			runtime := engine{preparationParentSync: func(root *os.Root, parent string) error {
				synced = append(synced, parent)
				// This callback is the sync operand itself, not a later error hook.
				if parent == failedParent {
					return syscall.EIO
				}
				return syncDirectory(root, parent)
			}}
			result, err := runtime.apply(context.Background(), rootPath, plan)
			if err != nil || result.State != StateRecoveryRequired || result.TransactionID != plan.TransactionID || result.AppliedCountKnown || result.AppliedCount != 0 || result.FailureClass != "journal_preparation_failed" {
				t.Fatalf("sync failure was misclassified: %#v %v", result, err)
			}
			if !reflect.DeepEqual(synced, []string{testResidueDirectory, ControlDirectory}) {
				t.Fatalf("did not attempt both parent syncs: %v", synced)
			}
			assertPreparationBeforeState(t, rootPath, terminalPath, terminal)
			assertPublishedPreparation(t, rootPath, plan)
			rolledBack, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryRollback)
			if err != nil || rolledBack.State != StateRolledBack || rolledBack.AppliedCount != 0 || !rolledBack.AppliedCountKnown {
				t.Fatalf("post-sync-error recovery: %#v %v", rolledBack, err)
			}
		})
	}
}

func TestPreparationRevalidatesBeforePromotion(t *testing.T) {
	for _, defect := range []string{
		"cancel", "active-empty", "active-with-evidence", "active-alias", "root-identity",
		"control-parent-identity", "control-identity", "residue-identity", "preparation-identity",
		"control-mode", "residue-mode", "preparation-mode", "journal-mode", "journal-bytes", "journal-symlink",
	} {
		t.Run(defect, func(t *testing.T) {
			rootPath, plan, _, _ := preparationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var retained []testTreeEntry
			observationRoot := rootPath
			reached := false
			runtime := engine{fault: func(point failurePoint, _ int) error {
				if point != faultBeforePreparationPublish {
					return nil
				}
				reached = true
				residues := preparationResidues(t, rootPath)
				if len(residues) != 1 {
					t.Fatal("missing preparation")
				}
				preparation := residues[0]
				mutate := func(err error) {
					if err != nil {
						t.Fatal(err)
					}
				}
				switch defect {
				case "cancel":
					cancel()
				case "active-empty", "active-with-evidence", "active-alias":
					name := activeDirectory
					if defect == "active-alias" {
						name = ControlDirectory + "/ACTIVE"
					}
					mutate(os.Mkdir(filepath.Join(rootPath, name), 0o700))
					if defect == "active-with-evidence" {
						mustWriteTestFile(t, rootPath, name+"/foreign", "evidence", 0o600)
					}
				case "root-identity":
					observationRoot = rootPath + "-retained"
					mutate(os.Rename(rootPath, observationRoot))
					mutate(os.Mkdir(rootPath, 0o700))
					t.Cleanup(func() {
						_ = os.Remove(rootPath)
						_ = os.Rename(observationRoot, rootPath)
					})
				case "control-parent-identity":
					mutate(os.Rename(filepath.Join(rootPath, ControlRoot), filepath.Join(rootPath, "old-control")))
					mutate(os.Mkdir(filepath.Join(rootPath, ControlRoot), 0o700))
					// Keep the locked inode and preparation in the replacement parent.
					mutate(os.Rename(filepath.Join(rootPath, "old-control/transactions"), filepath.Join(rootPath, ControlDirectory)))
					mutate(os.Rename(filepath.Join(rootPath, "old-control/transaction-residue"), filepath.Join(rootPath, testResidueDirectory)))
				case "control-identity", "residue-identity", "preparation-identity":
					name := ControlDirectory
					if defect == "residue-identity" {
						name = testResidueDirectory
					} else if defect == "preparation-identity" {
						name = preparation
					}
					mutate(os.Rename(filepath.Join(rootPath, name), filepath.Join(rootPath, name+"-retained")))
					mutate(os.Mkdir(filepath.Join(rootPath, name), 0o700))
					if defect == "preparation-identity" {
						data, err := os.ReadFile(filepath.Join(rootPath, name+"-retained/journal.json"))
						mutate(err)
						mustWriteTestFile(t, rootPath, name+"/journal.json", string(data), 0o600)
					}
				case "control-mode", "residue-mode", "preparation-mode", "journal-mode":
					name := ControlDirectory
					if defect == "residue-mode" {
						name = testResidueDirectory
					} else if defect == "preparation-mode" {
						name = preparation
					} else if defect == "journal-mode" {
						name = preparation + "/journal.json"
					}
					mutate(os.Chmod(filepath.Join(rootPath, name), 0o755))
				case "journal-bytes":
					mutate(os.WriteFile(filepath.Join(rootPath, preparation, "journal.json"), []byte("{}"), 0o600))
				case "journal-symlink":
					name := filepath.Join(rootPath, preparation, "journal.json")
					mutate(os.Rename(name, name+"-retained"))
					mutate(os.Symlink("journal.json-retained", name))
				}
				retained = snapshotTestTree(t, observationRoot)
				return nil
			}}
			result, err := runtime.apply(ctx, rootPath, plan)
			if !reached || err == nil || result != (Result{}) {
				t.Fatalf("drift admitted: reached=%v result=%#v error=%v", reached, result, err)
			}
			if defect == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if !reflect.DeepEqual(retained, snapshotTestTree(t, observationRoot)) {
				t.Fatal("rejected promotion mutated retained evidence")
			}
		})
	}
}

func TestPreparationAttemptsNeverReuseResidue(t *testing.T) {
	for _, collisionCount := range []int{1, 8} {
		t.Run(fmt.Sprint(collisionCount), func(t *testing.T) {
			rootPath := t.TempDir()
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := ensureDirectory(root, testResidueDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			colliding := testResidueDirectory + "/preparing-" + strings.Repeat("00", 16)
			mustWriteTestFile(t, rootPath, colliding+"/evidence", "retained", 0o600)
			before := snapshotTestTree(t, filepath.Join(rootPath, colliding))
			entropy := bytes.NewReader(append(make([]byte, collisionCount*16), bytes.Repeat([]byte{1}, 16)...))
			name, err := createPreparationDirectory(root, entropy)
			if collisionCount == 8 {
				if err == nil || name != "" || entropy.Len() != 16 {
					t.Fatalf("collision retry not bounded: name=%q error=%v unread=%d", name, err, entropy.Len())
				}
			} else if err != nil || name != testResidueDirectory+"/preparing-"+strings.Repeat("01", 16) {
				t.Fatalf("fresh attempt failed: %q %v", name, err)
			}
			if !reflect.DeepEqual(before, snapshotTestTree(t, filepath.Join(rootPath, colliding))) {
				t.Fatal("collision changed prior residue")
			}
		})
	}
}

func TestPreparationRetainedResidueIsNotReusedByNextApply(t *testing.T) {
	rootPath, plan, _, _ := preparationFixture(t)
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterPreparationPartialWrite {
			return syscall.ENOSPC
		}
		return nil
	}}
	if result, err := runtime.apply(context.Background(), rootPath, plan); err == nil || result != (Result{}) {
		t.Fatalf("partial failure: %#v %v", result, err)
	}
	residues := preparationResidues(t, rootPath)
	if len(residues) != 1 {
		t.Fatal("partial residue absent")
	}
	before := snapshotTestTree(t, filepath.Join(rootPath, residues[0]))
	replanned, err := BuildPlan(context.Background(), rootPath, preparationTargets())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, replanned); err != nil || result.State != StateApplied || result.AppliedCount != 3 {
		t.Fatalf("fresh apply: %#v %v", result, err)
	}
	if !reflect.DeepEqual(before, snapshotTestTree(t, filepath.Join(rootPath, residues[0]))) || !reflect.DeepEqual(residues, preparationResidues(t, rootPath)) {
		t.Fatal("fresh apply consumed or changed earlier preparation")
	}
}

func TestPreparationCancellationAfterRenameRetainsEvidence(t *testing.T) {
	rootPath, plan, terminalPath, terminal := preparationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := false
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterPreparationPublish {
			reached = true
			cancel()
		}
		return nil
	}}
	result, err := runtime.apply(ctx, rootPath, plan)
	if !reached || err != nil || result.State != StateRecoveryRequired || result.TransactionID != plan.TransactionID || result.AppliedCountKnown {
		t.Fatalf("published cancellation: %#v %v reached=%v", result, err, reached)
	}
	assertPreparationBeforeState(t, rootPath, terminalPath, terminal)
	assertPublishedPreparation(t, rootPath, plan)
}

func TestPreparationLockExcludesPlanningAtEachBoundary(t *testing.T) {
	rootPath, plan, _, _ := preparationFixture(t)
	var seen []failurePoint
	runtime := engine{fault: func(point failurePoint, _ int) error {
		switch point {
		case faultBeforePreparationMkdir, faultAfterPreparationMkdir, faultAfterPreparationPartialWrite, faultAfterPreparationPublish:
			seen = append(seen, point)
			if _, err := BuildPlan(context.Background(), rootPath, preparationTargets()); !errors.Is(err, ErrBusy) {
				t.Fatalf("live writer misclassified at %s: %v", point, err)
			}
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), rootPath, plan)
	if err != nil || result.State != StateApplied || len(seen) != 4 {
		t.Fatalf("live writer control: %#v %v boundaries=%v", result, err, seen)
	}
}

func TestPreparationRetentionDoesNotChangeOtherWriterCleanup(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(fmt.Sprint(retain), func(t *testing.T) {
			rootPath := t.TempDir()
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			reached := false
			err = writeOwnedFileWithRetention(root, "file", []byte("canonical"), 0o600, retain, func(point failurePoint, _ int) error {
				if point == faultAfterPreparationPartialWrite {
					reached = true
					return syscall.EIO
				}
				return nil
			})
			if !reached || !errors.Is(err, syscall.EIO) {
				t.Fatalf("write failure not reached: %v", err)
			}
			if retain {
				assertTestFile(t, rootPath, "file", "cano", 0o600)
			} else if _, err := os.Lstat(filepath.Join(rootPath, "file")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("non-preparation cleanup changed: %v", err)
			}
		})
	}
}
