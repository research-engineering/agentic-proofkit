package repositorytransaction

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInspectTerminalCompactionPrefixesRetainsRecoveryIdentity(t *testing.T) {
	for _, state := range []string{StateApplied, StateRolledBack} {
		for _, partial := range []bool{false, true} {
			t.Run(state+map[bool]string{false: "/archived", true: "/partial"}[partial], func(t *testing.T) {
				rootPath, plan, tombstone := nativeArchivedPrefix(t, state)
				if partial {
					if err := os.Remove(filepath.Join(rootPath, tombstone, "ready")); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(filepath.Join(rootPath, "state.json"))
				if err != nil {
					t.Fatal(err)
				}
				beforeTree := snapshotTestTree(t, rootPath)
				inspection, err := InspectControlState(t.Context(), rootPath)
				assertControlInspection(t, inspection, err, ControlStateRecoverable, plan.TransactionID)
				again, err := InspectControlState(t.Context(), rootPath)
				if err != nil || again != inspection {
					t.Fatalf("read-only inspection changed its observation: %v %v", again, err)
				}
				if !reflect.DeepEqual(snapshotTestTree(t, rootPath), beforeTree) {
					t.Fatal("terminal-prefix inspection mutated the repository")
				}
				action := RecoveryResume
				if state == StateRolledBack {
					action = RecoveryRollback
				}
				result, err := Recover(t.Context(), rootPath, plan.TransactionID, action)
				if err != nil || result.State != state {
					t.Fatalf("recovery = %#v, %v", result, err)
				}
				after, err := os.ReadFile(filepath.Join(rootPath, "state.json"))
				if err != nil || string(after) != string(before) {
					t.Fatalf("terminal cleanup changed target: %q %v", after, err)
				}
				inspection, err = InspectControlState(t.Context(), rootPath)
				assertControlInspection(t, inspection, err, ControlStateClean, "")
			})
		}
	}
}

func TestInspectTerminalCompactionRejectsUnknownAndInvalidResidue(t *testing.T) {
	for _, mutation := range []string{"unknown", "receipt", "symlink", "active-conflict"} {
		t.Run(mutation, func(t *testing.T) {
			rootPath, _, tombstone := nativeArchivedPrefix(t, StateApplied)
			switch mutation {
			case "unknown":
				if err := os.WriteFile(filepath.Join(rootPath, tombstone, "unexpected"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "receipt":
				if err := os.WriteFile(filepath.Join(rootPath, tombstone, terminalReceiptName), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := filepath.Join(rootPath, tombstone, "journal.json")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			case "active-conflict":
				if err := os.Mkdir(filepath.Join(rootPath, activeDirectory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			inspection, err := InspectControlState(t.Context(), rootPath)
			assertControlInspection(t, inspection, err, ControlStateInvalid, "")
		})
	}
}

func nativeArchivedPrefix(t *testing.T, state string) (string, Plan, string) {
	t.Helper()
	ctx := context.Background()
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "state.json"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(ctx, rootPath, []Target{{Path: "state.json", Content: []byte("desired\n"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	lock, err := acquireTransactionLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	if _, err := (engine{}).prepareJournal(context.Background(), root, lock, plan); err != nil {
		t.Fatal(err)
	}
	if err := stageObjects(root, plan); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(root, readyMarker); err != nil {
		t.Fatal(err)
	}
	if err := (engine{}).applyForward(ctx, root, plan, 0); err != nil {
		t.Fatal(err)
	}
	result := Result{AppliedCount: 1, AppliedCountKnown: true, State: state, TransactionID: plan.TransactionID}
	if state == StateRolledBack {
		if err := selectRecoveryAction(root, plan.TransactionID, RecoveryRollback); err != nil {
			t.Fatal(err)
		}
		if err := (engine{}).rollbackPrefix(ctx, root, plan, 1); err != nil {
			t.Fatal(err)
		}
		if err := writeMarker(root, rolledBackMarker); err != nil {
			t.Fatal(err)
		}
		result.AppliedCount = 0
		result.RecoveredBy = RecoveryRollback
	} else if err := writeMarker(root, committedMarker); err != nil {
		t.Fatal(err)
	}
	tombstone, err := archiveTerminal(root, plan, result)
	if err != nil {
		t.Fatal(err)
	}
	return rootPath, plan, tombstone
}
