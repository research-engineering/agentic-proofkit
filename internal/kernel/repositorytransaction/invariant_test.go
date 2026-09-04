package repositorytransaction

import (
	"context"
	"errors"
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

func TestLateDirectoryIsNeverClaimedOrRemoved(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "new/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterReady {
			if err := os.Mkdir(filepath.Join(root, "new"), 0o755); err != nil {
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
