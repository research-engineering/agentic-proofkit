package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func deletionRecoveryTargets() []Target {
	return []Target{
		{Path: "a", Absent: true},
		{Path: "b", Content: []byte("new-b"), Mode: 0o644},
		{Path: "c", Mode: 0o644},
		{Path: "d/missing", Absent: true},
		{Path: "z/new", Content: []byte("new-z"), Mode: 0o644},
	}
}

func seedDeletionRecovery(t *testing.T, root string) Plan {
	t.Helper()
	mustWriteTestFile(t, root, "a", "old-a", 0o600)
	mustWriteTestFile(t, root, "b", "old-b", 0o640)
	mustWriteTestFile(t, root, "c", "", 0o644)
	plan, err := BuildPlan(context.Background(), root, deletionRecoveryTargets())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func assertDeletionRecoveryFiles(t *testing.T, root, state string) {
	t.Helper()
	assertTestFile(t, root, "c", "", 0o644)
	assertAbsentTestPath(t, root, "d")
	if state == StateApplied {
		assertAbsentTestPath(t, root, "a")
		assertTestFile(t, root, "b", "new-b", 0o644)
		assertTestFile(t, root, "z/new", "new-z", 0o644)
	} else {
		assertTestFile(t, root, "a", "old-a", 0o600)
		assertTestFile(t, root, "b", "old-b", 0o640)
		assertAbsentTestPath(t, root, "z")
	}
}

func TestDeletionRecoversEveryMixedPrefixAndHistoricalResult(t *testing.T) {
	t.Run("observation-partition", testRecoveryObservationPartition)
	t.Run("cancellation-commit-boundary", testDeletionCancellationCommitBoundary)
	for _, action := range []string{RecoveryResume, RecoveryRollback} {
		for prefix := 0; prefix <= 3; prefix++ {
			t.Run(fmt.Sprintf("%s-%d", action, prefix), func(t *testing.T) {
				rootPath := t.TempDir()
				plan := seedDeletionRecovery(t, rootPath)
				leaveDeletionPrefix(t, rootPath, plan, prefix)
				result, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
				want := StateApplied
				if action == RecoveryRollback {
					want = StateRolledBack
				}
				if err != nil || result.State != want || result.RecoveredBy != action {
					t.Fatalf("recover: %#v %v", result, err)
				}
				assertDeletionRecoveryFiles(t, rootPath, want)
				assertNoPendingTransaction(t, rootPath)
				if action == RecoveryResume {
					mustWriteTestFile(t, rootPath, "a", "recreated", 0o644)
				}
				before := snapshotTestTree(t, rootPath)
				repeated, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
				if err != nil || repeated != result || !reflect.DeepEqual(before, snapshotTestTree(t, rootPath)) {
					t.Fatalf("historical recovery changed result or repository: %#v %v", repeated, err)
				}
			})
		}
	}
}

func TestDeletionRejectsMissingCorruptAndUnexpectedStagedObjects(t *testing.T) {
	for _, corruption := range []string{"missing-before", "corrupt-before", "unexpected-after", "unexpected-unchanged"} {
		t.Run(corruption, func(t *testing.T) {
			root := t.TempDir()
			plan := seedDeletionRecovery(t, root)
			leaveDeletionPrefix(t, root, plan, 1)
			switch corruption {
			case "missing-before":
				if err := os.Remove(filepath.Join(root, beforeObjectPath(0))); err != nil {
					t.Fatal(err)
				}
			case "corrupt-before":
				mustWriteTestFile(t, root, beforeObjectPath(0), "wrong", 0o600)
			case "unexpected-after":
				mustWriteTestFile(t, root, afterObjectPath(0), "", 0o600)
			case "unexpected-unchanged":
				mustWriteTestFile(t, root, afterObjectPath(3), "", 0o600)
			}
			before := snapshotTestTree(t, root)
			result, err := Recover(context.Background(), root, plan.TransactionID, RecoveryRollback)
			if err != nil || result.State != StateRecoveryRequired || !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
				t.Fatalf("invalid staging: %#v %v", result, err)
			}
		})
	}
}

func TestDeletionProcessInterruptionAtMutationBoundaries(t *testing.T) {
	if point := os.Getenv("PROOFKIT_DELETE_CRASH_POINT"); point != "" {
		root := os.Getenv("PROOFKIT_DELETE_CRASH_ROOT")
		plan, err := BuildPlan(context.Background(), root, deletionRecoveryTargets())
		if err != nil {
			t.Fatal(err)
		}
		runtime := engine{fault: func(actual failurePoint, index int) error {
			if actual == failurePoint(point) {
				os.Exit(73)
			}
			if point == string(faultAfterRollback) && actual == faultAfterPublish && index == 2 {
				return errors.New("trigger reverse rollback")
			}
			return nil
		}}
		result, err := runtime.apply(context.Background(), root, plan)
		t.Fatalf("crash boundary not reached: %#v %v", result, err)
	}
	for _, point := range []failurePoint{faultAfterJournal, faultAfterStaging, faultAfterReady, faultAfterDirectory, faultBeforePublish, faultAfterPublish, faultAfterRollback, faultAfterTerminal, faultBeforeCleanup, faultAfterStateRemoval} {
		t.Run(string(point), func(t *testing.T) {
			root := t.TempDir()
			plan := seedDeletionRecovery(t, root)
			command := exec.Command(os.Args[0], "-test.run=^TestDeletionProcessInterruptionAtMutationBoundaries$")
			command.Env = append(os.Environ(), "PROOFKIT_DELETE_CRASH_POINT="+string(point), "PROOFKIT_DELETE_CRASH_ROOT="+root)
			err := command.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("crash helper: %v", err)
			}
			action, want := RecoveryRollback, StateRolledBack
			if point == faultAfterTerminal || point == faultBeforeCleanup || point == faultAfterStateRemoval {
				action, want = RecoveryResume, StateApplied
			}
			result, err := Recover(context.Background(), root, plan.TransactionID, action)
			if err != nil || result.State != want || result.RecoveredBy != action {
				t.Fatalf("recover: %#v %v", result, err)
			}
			assertDeletionRecoveryFiles(t, root, want)
			assertNoPendingTransaction(t, root)
		})
	}
}

func leaveDeletionPrefix(t *testing.T, rootPath string, plan Plan, prefix int) {
	t.Helper()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := prepareJournal(root, plan); err != nil {
		t.Fatal(err)
	}
	if err := stageObjects(root, plan); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(root, readyMarker); err != nil {
		t.Fatal(err)
	}
	if err := ensureTargetDirectories(root, plan); err != nil {
		t.Fatal(err)
	}
	// Recovery input uses direct effects, not the forward executor under test.
	if prefix > 0 {
		if err := os.Remove(filepath.Join(rootPath, "a")); err != nil {
			t.Fatal(err)
		}
	}
	if prefix > 1 {
		mustWriteTestFile(t, rootPath, "b", "new-b", 0o644)
		if err := os.Chmod(filepath.Join(rootPath, "b"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if prefix > 2 {
		mustWriteTestFile(t, rootPath, "z/new", "new-z", 0o644)
	}
}
