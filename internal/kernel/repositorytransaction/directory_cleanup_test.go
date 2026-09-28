package repositorytransaction

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOwnershipWriteFailureRetainsRecoverableDirectory(t *testing.T) {
	for _, publish := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-publication", true: "after-publication"}[publish], func(t *testing.T) {
			rootPath, plan := readyDirectoryOwnershipFixture(t)
			calls := 0
			failure := errors.New("synthetic ownership acknowledgement failure")
			var publishedIdentity string
			runtime := engine{directoryOwnershipWrite: func(root *os.Root, index int, record directoryOwnership) error {
				calls++
				publishedIdentity = record.Identity
				if publish {
					if err := writeDirectoryOwnership(root, index, record); err != nil {
						return err
					}
				}
				return failure
			}}
			result, err := runtime.recover(t.Context(), rootPath, plan.TransactionID, RecoveryResume)
			if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "resume_failed" || calls != 1 {
				t.Fatalf("write failure not observed: result=%#v error=%v calls=%d", result, err, calls)
			}
			info, err := os.Stat(filepath.Join(rootPath, "new"))
			if err != nil {
				t.Fatal("uncertain publication lost its owned directory")
			}
			identity, err := platformFileIdentity(info)
			if err != nil || identity != publishedIdentity || info.Mode().Perm() != 0755 {
				t.Fatalf("directory identity/mode changed: identity=%q mode=%v error=%v", identity, info.Mode(), err)
			}
			_, recordErr := os.Stat(filepath.Join(rootPath, directoryOwnershipPath(0)))
			if (recordErr == nil) != publish || (recordErr != nil && !os.IsNotExist(recordErr)) {
				t.Fatalf("wrong publication state: published=%v error=%v", publish, recordErr)
			}
			if !publish {
				again, err := runtime.recover(t.Context(), rootPath, plan.TransactionID, RecoveryResume)
				if err != nil || again.State != StateRecoveryRequired || calls != 2 {
					t.Fatalf("persistent pre-publication failure disappeared: %#v %v calls=%d", again, err, calls)
				}
			}
			// The public default engine must not inherit the failed engine's callback.
			resumed, err := Recover(t.Context(), rootPath, plan.TransactionID, RecoveryResume)
			if err != nil || resumed.State != StateApplied || !resumed.AppliedCountKnown || resumed.AppliedCount != 1 {
				t.Fatalf("repeat selected resume did not complete: %#v %v", resumed, err)
			}
			assertTestFile(t, rootPath, "new/target.txt", "desired\n", 0644)
			after, err := os.Stat(filepath.Join(rootPath, "new"))
			if err != nil || !os.SameFile(info, after) {
				t.Fatal("resume replaced owned directory")
			}
			before := snapshotTestTree(t, rootPath)
			repeated, err := Recover(t.Context(), rootPath, plan.TransactionID, RecoveryResume)
			if err != nil || repeated != resumed {
				t.Fatalf("terminal repeat changed: %#v %v", repeated, err)
			}
			if !reflect.DeepEqual(before, snapshotTestTree(t, rootPath)) {
				t.Fatal("terminal repeat changed retained state")
			}
		})
	}
}

func TestOwnershipWriteErrorPreservesDefaultRollbackOwner(t *testing.T) {
	for _, publish := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-publication", true: "after-publication"}[publish], func(t *testing.T) {
			rootPath := t.TempDir()
			plan, err := BuildPlan(t.Context(), rootPath, []Target{{Path: "new/target.txt", Content: []byte("desired\n"), Mode: 0644}})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			runtime := engine{directoryOwnershipWrite: func(root *os.Root, index int, record directoryOwnership) error {
				calls++
				if publish {
					if err := writeDirectoryOwnership(root, index, record); err != nil {
						return err
					}
				}
				return errors.New("synthetic ownership acknowledgement failure")
			}}
			result, err := runtime.apply(t.Context(), rootPath, plan)
			if err != nil || result.State != StateRolledBack || result.FailureClass != "publication_failed" || calls != 1 {
				t.Fatalf("automatic rollback changed: %#v %v calls=%d", result, err, calls)
			}
			assertAbsentTestPath(t, rootPath, "new")
			assertNoActiveTransaction(t, rootPath)
		})
	}
}

func TestOwnershipWriteFailureAllowsExplicitRollback(t *testing.T) {
	for _, publish := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-publication", true: "after-publication"}[publish], func(t *testing.T) {
			rootPath, plan := readyDirectoryOwnershipFixture(t)
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("synthetic ownership acknowledgement failure")
			calls := 0
			runtime := engine{directoryOwnershipWrite: func(root *os.Root, index int, record directoryOwnership) error {
				calls++
				if publish {
					if err := writeDirectoryOwnership(root, index, record); err != nil {
						return err
					}
				}
				return failure
			}}
			writeErr := runtime.ensureTargetDirectories(root, plan)
			closeErr := root.Close()
			if !errors.Is(writeErr, failure) || closeErr != nil || calls != 1 {
				t.Fatalf("ownership error classification changed: write=%v close=%v calls=%d", writeErr, closeErr, calls)
			}
			result, err := Recover(t.Context(), rootPath, plan.TransactionID, RecoveryRollback)
			if err != nil || result.State != StateRolledBack || result.RecoveredBy != RecoveryRollback || !result.AppliedCountKnown || result.AppliedCount != 0 {
				t.Fatalf("explicit rollback failed: %#v %v", result, err)
			}
			assertAbsentTestPath(t, rootPath, "new")
			assertNoActiveTransaction(t, rootPath)
		})
	}
}

func readyDirectoryOwnershipFixture(t *testing.T) (string, Plan) {
	t.Helper()
	rootPath := t.TempDir()
	plan, err := BuildPlan(t.Context(), rootPath, []Target{{Path: "new/target.txt", Content: []byte("desired\n"), Mode: 0644}})
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
	lock, err := acquireTransactionLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.releaseChecked(); err != nil {
			t.Error(err)
		}
	}()
	if published, err := (engine{}).prepareJournal(t.Context(), root, lock, plan); err != nil || !published {
		t.Fatalf("prepare ready journal: published=%v error=%v", published, err)
	}
	if err := stageObjects(root, plan); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(root, readyMarker); err != nil {
		t.Fatal(err)
	}
	return rootPath, plan
}

func TestDirectoryAdmissionIncludesCloseOutcome(t *testing.T) {
	operationFailure := errors.New("initial admission failure")
	closeFailure := errors.New("underlying private close detail")
	for _, item := range []struct {
		name         string
		operationErr error
		closeErr     error
	}{
		{name: "success"},
		{name: "admission failure", operationErr: operationFailure},
		{name: "close failure", closeErr: closeFailure},
		{name: "both failures", operationErr: operationFailure, closeErr: closeFailure},
	} {
		t.Run(item.name, func(t *testing.T) {
			closer := &directoryCloseOutcome{err: item.closeErr}
			identity, exists, resultErr := "observed-directory", true, item.operationErr
			closeDirectoryAdmission(closer, &identity, &exists, &resultErr)
			if closer.calls != 1 {
				t.Fatalf("close calls = %d, want one", closer.calls)
			}
			if item.operationErr == nil && item.closeErr == nil {
				if identity != "observed-directory" || !exists || resultErr != nil {
					t.Fatalf("successful observation changed: %q %v %v", identity, exists, resultErr)
				}
				return
			}
			if identity != "" || exists || resultErr == nil {
				t.Fatalf("failed observation retained authority: %q %v %v", identity, exists, resultErr)
			}
			if item.operationErr != nil && !errors.Is(resultErr, operationFailure) {
				t.Fatalf("initial error lost: %v", resultErr)
			}
			if errors.Is(resultErr, ErrReadCleanup) != (item.closeErr != nil) {
				t.Fatalf("cleanup classification changed: %v", resultErr)
			}
			if strings.Contains(resultErr.Error(), closeFailure.Error()) {
				t.Fatalf("private close diagnostic was disclosed: %v", resultErr)
			}
		})
	}
}

type directoryCloseOutcome struct {
	err   error
	calls int
}

func (closer *directoryCloseOutcome) Close() error {
	closer.calls++
	return closer.err
}
