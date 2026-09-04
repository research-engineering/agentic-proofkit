package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyExecutesFrozenPlan(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "proofkit"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterReady {
			plan.Operations[0].Path = "proofkit/redirected.json"
			plan.Operations[0].afterContent[0] = 'X'
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), root, plan)
	if err != nil || result.State != StateApplied {
		t.Fatalf("apply() result=%#v error=%v", result, err)
	}
	assertTestFile(t, root, "proofkit/target.json", "desired\n", 0o644)
	if _, err := os.Stat(filepath.Join(root, "proofkit", "redirected.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("caller mutation redirected an admitted effect: %v", err)
	}
}

func TestApplyDoesNotRemoveUnownedNeighbourTemporary(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "proofkit"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	oldTemporary := filepath.Join(root, "proofkit", ".agentic-proofkit-txn-"+strings.TrimPrefix(plan.TransactionID, "sha256:")+"-000.tmp")
	if err := os.WriteFile(oldTemporary, []byte("caller-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Apply(context.Background(), root, plan)
	if err != nil || result.State != StateApplied {
		t.Fatalf("Apply() result=%#v error=%v", result, err)
	}
	content, err := os.ReadFile(oldTemporary)
	if err != nil || string(content) != "caller-owned\n" {
		t.Fatalf("Apply() changed an undeclared neighbour: %q, %v", content, err)
	}
}

func TestNonEmptyLateDirectoryIsNeverClaimedOrRemoved(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "new/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterReady {
			if err := os.Mkdir(filepath.Join(root, "new"), 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "new", "foreign.txt"), []byte("foreign\n"), 0o644)
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), root, plan)
	if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "directory_cleanup_failed" {
		t.Fatalf("apply() result=%#v error=%v", result, err)
	}
	assertTestFile(t, root, "new/foreign.txt", "foreign\n", 0o644)
	if info, err := os.Stat(filepath.Join(root, "new")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("rejected late directory mode=%v error=%v, want 0700", infoMode(info), err)
	}
}

func TestDirectoryOwnershipRejectsInodeSubstitution(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "new/nested/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, root, plan, 0)
	if err := os.Rename(filepath.Join(root, "new"), filepath.Join(root, "captured")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(context.Background(), root, plan.TransactionID, RecoveryRollback)
	if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "directory_cleanup_failed" {
		t.Fatalf("Recover() result=%#v error=%v", result, err)
	}
	if info, err := os.Stat(filepath.Join(root, "new")); err != nil || !info.IsDir() {
		t.Fatalf("substituted directory was removed: %v", err)
	}
}

func TestDirectoryOwnershipRejectsPortableRouteAlias(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "new/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	intermediate := filepath.Join(rootPath, "renaming")
	if err := os.Rename(filepath.Join(rootPath, "new"), intermediate); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(intermediate, filepath.Join(rootPath, "New")); err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectOwnedTargetDirectory(root, "new"); err == nil || !strings.Contains(err.Error(), "portable filesystem identity") {
		root.Close()
		t.Fatalf("inspectOwnedTargetDirectory() error=%v, want portable-alias rejection", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryRollback)
	if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "ambiguous_target_state" {
		t.Fatalf("Recover() result=%#v error=%v", result, err)
	}
	if info, err := os.Stat(filepath.Join(rootPath, "New")); err != nil || !info.IsDir() {
		t.Fatalf("portable directory alias was removed: %v", err)
	}
}

func TestRecoveryActionAndTerminalReceiptAreStable(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, root, plan, 0)
	transactionRoot, _, err := openRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(transactionRoot, rolledBackMarker); err != nil {
		transactionRoot.Close()
		t.Fatal(err)
	}
	if err := transactionRoot.Close(); err != nil {
		t.Fatal(err)
	}
	mismatch, err := Recover(context.Background(), root, plan.TransactionID, RecoveryResume)
	if err != nil || mismatch.State != StateRecoveryRequired || mismatch.FailureClass != "rolled_back_state_mismatch" {
		t.Fatalf("Recover(resume active rollback)=%#v, %v", mismatch, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := Recover(context.Background(), root, plan.TransactionID, RecoveryRollback)
		if err != nil || result.State != StateRolledBack || result.RecoveredBy != RecoveryRollback || !result.AppliedCountKnown || result.AppliedCount != 0 {
			t.Fatalf("Recover(rollback attempt %d)=%#v, %v", attempt, result, err)
		}
	}
	mismatch, err = Recover(context.Background(), root, plan.TransactionID, RecoveryResume)
	if err != nil || mismatch.State != StateRecoveryRequired || mismatch.FailureClass != "rolled_back_state_mismatch" {
		t.Fatalf("Recover(resume terminal rollback)=%#v, %v", mismatch, err)
	}
}

func TestRecoveryActionIsDurableBeforeDirectionalMutation(t *testing.T) {
	tests := []struct {
		name           string
		firstAction    string
		opposite       string
		prefix         int
		failurePoint   failurePoint
		wantAAfter     string
		wantBAfter     string
		wantFinalState string
	}{
		{name: "resume", firstAction: RecoveryResume, opposite: RecoveryRollback, prefix: 0, failurePoint: faultAfterPublish, wantAAfter: "after-a\n", wantBAfter: "before-b\n", wantFinalState: StateApplied},
		{name: "rollback", firstAction: RecoveryRollback, opposite: RecoveryResume, prefix: 2, failurePoint: faultAfterRollback, wantAAfter: "after-a\n", wantBAfter: "before-b\n", wantFinalState: StateRolledBack},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			mustWriteTestFile(t, rootPath, "proofkit/a.json", "before-a\n", 0o644)
			mustWriteTestFile(t, rootPath, "proofkit/b.json", "before-b\n", 0o644)
			plan, err := BuildPlan(context.Background(), rootPath, []Target{
				{Path: "proofkit/a.json", Content: []byte("after-a\n"), Mode: 0o644},
				{Path: "proofkit/b.json", Content: []byte("after-b\n"), Mode: 0o644},
			})
			if err != nil {
				t.Fatal(err)
			}
			leaveInterruptedPrefix(t, rootPath, plan, test.prefix)
			runtime := engine{fault: func(point failurePoint, index int) error {
				if point == test.failurePoint && index == 1 {
					return errors.New("injected directional interruption")
				}
				return nil
			}}
			result, err := runtime.recover(context.Background(), rootPath, plan.TransactionID, test.firstAction)
			if err != nil || result.State != StateRecoveryRequired {
				t.Fatalf("first Recover()=%#v, %v", result, err)
			}
			assertTestFile(t, rootPath, "proofkit/a.json", test.wantAAfter, 0o644)
			assertTestFile(t, rootPath, "proofkit/b.json", test.wantBAfter, 0o644)

			mismatch, err := Recover(context.Background(), rootPath, plan.TransactionID, test.opposite)
			if err != nil || mismatch.State != StateRecoveryRequired || mismatch.FailureClass != "recovery_action_mismatch" {
				t.Fatalf("opposite Recover()=%#v, %v", mismatch, err)
			}
			completed, err := Recover(context.Background(), rootPath, plan.TransactionID, test.firstAction)
			if err != nil || completed.State != test.wantFinalState || completed.RecoveredBy != test.firstAction {
				t.Fatalf("stable Recover()=%#v, %v", completed, err)
			}
		})
	}
}

func TestMalformedRecoveryActionBlocksMutation(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteTestFile(t, rootPath, "proofkit/target.json", "before\n", 0o644)
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/target.json", Content: []byte("after\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, recoveryActionPath, []byte(`{"action":"resume"}`), 0o600); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "invalid_recovery_action" {
		t.Fatalf("Recover()=%#v, %v", result, err)
	}
	assertTestFile(t, rootPath, "proofkit/target.json", "before\n", 0o644)
	content, err := os.ReadFile(filepath.Join(rootPath, filepath.FromSlash(recoveryActionPath)))
	if err != nil || string(content) != `{"action":"resume"}` {
		t.Fatalf("rejected action record changed: content=%q err=%v", content, err)
	}
}

func TestPreparingFailureCannotClaimRollbackAfterTargetDivergence(t *testing.T) {
	root := t.TempDir()
	mustWriteTestFile(t, root, "proofkit/state.json", "before\n", 0o644)
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point != faultAfterStaging {
			return nil
		}
		mustWriteTestFile(t, root, "proofkit/state.json", "concurrent\n", 0o644)
		return errors.New("injected preparation failure")
	}}
	result, err := runtime.apply(context.Background(), root, plan)
	if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "preparing_state_mismatch" {
		t.Fatalf("apply() result=%#v error=%v", result, err)
	}
	assertTestFile(t, root, "proofkit/state.json", "concurrent\n", 0o644)
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(journalPath))); err != nil {
		t.Fatalf("preparing mismatch removed its recovery journal: %v", err)
	}
	recovery, err := Recover(context.Background(), root, plan.TransactionID, RecoveryRollback)
	if err != nil || recovery.State != StateRecoveryRequired || recovery.FailureClass != "preparing_state_mismatch" {
		t.Fatalf("Recover() result=%#v error=%v", recovery, err)
	}
}

func TestAppliedTerminalReceiptReplaysCompleteResult(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{
		{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644},
		{Path: "proofkit/b.json", Content: []byte("b\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), root, plan); err != nil || result.State != StateApplied || result.AppliedCount != 2 {
		t.Fatalf("Apply()=%#v, %v", result, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := Recover(context.Background(), root, plan.TransactionID, RecoveryResume)
		if err != nil || result.State != StateApplied || result.RecoveredBy != RecoveryResume || !result.AppliedCountKnown || result.AppliedCount != 2 {
			t.Fatalf("Recover(attempt %d)=%#v, %v", attempt, result, err)
		}
	}
}

func TestCommittedRecoveryRejectsRollback(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterTerminal {
			return errors.New("injected")
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), root, plan)
	if err != nil || result.State != StateCleanupRequired {
		t.Fatalf("apply() result=%#v error=%v", result, err)
	}
	mismatch, err := Recover(context.Background(), root, plan.TransactionID, RecoveryRollback)
	if err != nil || mismatch.State != StateRecoveryRequired || mismatch.FailureClass != "committed_state_mismatch" {
		t.Fatalf("Recover(rollback committed)=%#v, %v", mismatch, err)
	}
}

func TestUnknownRecoveryStateDoesNotAdoptExpectedIdentity(t *testing.T) {
	root := t.TempDir()
	unknown := filepath.Join(root, ControlDirectory, "unknown")
	if err := os.MkdirAll(unknown, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(root, ControlRoot), filepath.Join(root, ControlDirectory), unknown} {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	expected := "sha256:" + strings.Repeat("7", 64)
	result, err := Recover(context.Background(), root, expected, RecoveryRollback)
	if err != nil || result.State != StateRecoveryRequired || result.TransactionID != "" {
		t.Fatalf("Recover() result=%#v error=%v", result, err)
	}
}

func TestRejectedApplyPreservesPreviousTerminalReceipt(t *testing.T) {
	root := t.TempDir()
	first, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/first.json", Content: []byte("first\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), root, first); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(first)=%#v, %v", result, err)
	}
	mustWriteTestFile(t, root, "proofkit/second.json", "before\n", 0o644)
	second, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/second.json", Content: []byte("after\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, root, "proofkit/second.json", "concurrent\n", 0o644)
	if _, err := Apply(context.Background(), root, second); err == nil {
		t.Fatal("Apply(second) admitted stale input")
	}
	replayed, err := Recover(context.Background(), root, first.TransactionID, RecoveryResume)
	if err != nil || replayed.State != StateApplied {
		t.Fatalf("Recover(first)=%#v, %v", replayed, err)
	}
}

func TestPreparingRollbackAtomicallyReplacesPreviousTerminalReceipt(t *testing.T) {
	rootPath := t.TempDir()
	first, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/first.json", Content: []byte("first\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, first); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(first)=%#v, %v", result, err)
	}
	second, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/second.json", Content: []byte("second\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareJournal(root, second); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := stageObjects(root, second); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/third.json", Content: []byte("third\n"), Mode: 0o644}}); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("BuildPlan() error=%v, want recovery required", err)
	} else if transactionID, ok := RecoveryTransactionID(err); !ok || transactionID != second.TransactionID {
		t.Fatalf("RecoveryTransactionID()=%q,%t, want %q,true", transactionID, ok, second.TransactionID)
	}
	retained, err := ReadTerminalResult(context.Background(), rootPath, first.TransactionID)
	if err != nil || retained.State != StateApplied {
		t.Fatalf("ReadTerminalResult(first)=%#v, %v", retained, err)
	}
	rolledBack, err := Recover(context.Background(), rootPath, second.TransactionID, RecoveryRollback)
	if err != nil || rolledBack.State != StateRolledBack {
		t.Fatalf("Recover(second)=%#v, %v", rolledBack, err)
	}
	if _, err := ReadTerminalResult(context.Background(), rootPath, first.TransactionID); err == nil {
		t.Fatal("terminalized preparing rollback retained the superseded receipt")
	}
	retained, err = ReadTerminalResult(context.Background(), rootPath, second.TransactionID)
	if err != nil || retained != rolledBack {
		t.Fatalf("ReadTerminalResult(second)=%#v, %v, want %#v", retained, err, rolledBack)
	}
	replayed, err := Recover(context.Background(), rootPath, second.TransactionID, RecoveryRollback)
	if err != nil || replayed != rolledBack {
		t.Fatalf("Recover(second replay)=%#v, %v, want %#v", replayed, err, rolledBack)
	}
}

func TestReadyReplacementRetiresPreviousReceiptAndPreservesCompleteResult(t *testing.T) {
	rootPath := t.TempDir()
	first, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/first.json", Content: []byte("first\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, first); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(first)=%#v, %v", result, err)
	}
	second, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/second.json", Content: []byte("second\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterReady {
			return errors.New("injected")
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), rootPath, second)
	if err != nil || result.State != StateRolledBack || result.FailureClass != "injected_apply_failure" {
		t.Fatalf("Apply(second)=%#v, %v", result, err)
	}
	if _, err := ReadTerminalResult(context.Background(), rootPath, first.TransactionID); err == nil {
		t.Fatal("ready replacement retained the superseded terminal receipt")
	}
	retained, err := ReadTerminalResult(context.Background(), rootPath, second.TransactionID)
	if err != nil || retained != result {
		t.Fatalf("ReadTerminalResult(second)=%#v, %v, want %#v", retained, err, result)
	}
}

func TestRecoveryCompletesReadyReplacementWithPreviousReceipt(t *testing.T) {
	rootPath := t.TempDir()
	first, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/first.json", Content: []byte("first\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), rootPath, first); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(first)=%#v, %v", result, err)
	}
	second, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/second.json", Content: []byte("second\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareJournal(root, second); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := stageObjects(root, second); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := writeMarker(root, readyMarker); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(context.Background(), rootPath, second.TransactionID, RecoveryRollback)
	if err != nil || result.State != StateRolledBack || result.RecoveredBy != RecoveryRollback {
		t.Fatalf("Recover(second)=%#v, %v", result, err)
	}
	if _, err := ReadTerminalResult(context.Background(), rootPath, first.TransactionID); err == nil {
		t.Fatal("ready recovery retained the superseded terminal receipt")
	}
	retained, err := ReadTerminalResult(context.Background(), rootPath, second.TransactionID)
	if err != nil || retained != result {
		t.Fatalf("ReadTerminalResult(second)=%#v, %v, want %#v", retained, err, result)
	}
}

func TestApplyCompletesInterruptedTerminalRetirement(t *testing.T) {
	for _, receiptPresent := range []bool{true, false} {
		t.Run(fmt.Sprintf("receipt-present=%t", receiptPresent), func(t *testing.T) {
			rootPath := t.TempDir()
			first, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/first.json", Content: []byte("first\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := Apply(context.Background(), rootPath, first); err != nil || result.State != StateApplied {
				t.Fatalf("Apply(first)=%#v, %v", result, err)
			}
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			terminalPath := terminalTombstonePath(first.TransactionID, StateApplied)
			retiredPath := retiredTerminalTombstonePath(first.TransactionID, StateApplied)
			if err := root.Rename(filepath.FromSlash(terminalPath), filepath.FromSlash(retiredPath)); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if !receiptPresent {
				if err := root.Remove(filepath.FromSlash(retiredPath + "/" + terminalReceiptName)); err != nil {
					root.Close()
					t.Fatal(err)
				}
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}

			if receiptPresent {
				retained, err := ReadTerminalResult(context.Background(), rootPath, first.TransactionID)
				if err != nil || retained.State != StateApplied {
					t.Fatalf("ReadTerminalResult()=%#v, %v", retained, err)
				}
			}
			second, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/second.json", Content: []byte("second\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := Apply(context.Background(), rootPath, second); err != nil || result.State != StateApplied {
				t.Fatalf("Apply(second)=%#v, %v", result, err)
			}
			assertTestFile(t, rootPath, "proofkit/second.json", "second\n", 0o644)
			assertNoPendingTransaction(t, rootPath)
		})
	}
}
