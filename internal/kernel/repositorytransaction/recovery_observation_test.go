package repositorytransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testRecoveryObservationPartition(t *testing.T) {
	for _, phase := range []string{"preparing-temp", "preparing", "ready", "committed", "rolled-back"} {
		for _, observation := range []string{"unchanged", "content", "directory", "parent"} {
			t.Run(phase+"/"+observation, func(t *testing.T) {
				rootPath := t.TempDir()
				plan := seedDeletionRecovery(t, rootPath)
				prefix, action, want := 0, RecoveryRollback, StateRolledBack
				if phase == "committed" {
					prefix, action, want = 3, RecoveryResume, StateApplied
				}
				if phase != "preparing-temp" {
					leaveDeletionPrefix(t, rootPath, plan, prefix)
				}
				root, _, err := openRepository(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				switch phase {
				case "preparing-temp":
					err = prepareJournal(root, plan)
					if err == nil {
						err = root.Rename(journalPath, journalTemp)
					}
				case "preparing":
					err = root.Remove(readyMarker)
				case "committed":
					err = writeMarker(root, committedMarker)
				case "rolled-back":
					err = writeMarker(root, rolledBackMarker)
				}
				if closeErr := root.Close(); err != nil || closeErr != nil {
					t.Fatal(errors.Join(err, closeErr))
				}
				switch observation {
				case "content":
					mustWriteTestFile(t, rootPath, "b", "foreign", 0o640)
				case "directory":
					if err := os.Remove(filepath.Join(rootPath, "b")); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(filepath.Join(rootPath, "b"), 0o700); err != nil {
						t.Fatal(err)
					}
				case "parent":
					if err := os.Remove(filepath.Join(rootPath, "z/new")); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
					if err := os.Remove(filepath.Join(rootPath, "z")); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
					mustWriteTestFile(t, rootPath, "z", "foreign parent", 0o600)
				}
				before := snapshotTestTree(t, rootPath)
				result, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
				if observation == "unchanged" {
					if err != nil || result.State != want || result.RecoveredBy != action {
						t.Fatalf("valid recovery fixture rejected: %#v %v", result, err)
					}
					assertDeletionRecoveryFiles(t, rootPath, want)
					return
				}
				if observation == "content" {
					if err != nil || result.State != StateRecoveryRequired || result.TransactionID != plan.TransactionID {
						t.Fatalf("observed mismatch became operational: %#v %v", result, err)
					}
				} else if err == nil || result != (Result{}) {
					t.Fatalf("observation failure became a classified result: %#v %v", result, err)
				}
				if !reflect.DeepEqual(before, snapshotTestTree(t, rootPath)) {
					t.Fatal("rejected observation changed target or control state")
				}
			})
		}
	}
}
