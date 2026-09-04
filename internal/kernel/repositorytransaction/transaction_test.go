package repositorytransaction

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestApplyCommitsAndRepeatedPlanIsAlreadySatisfied(t *testing.T) {
	root := t.TempDir()
	mustWriteTestFile(t, root, "proofkit/existing.json", "before\n", 0o600)
	targets := []Target{
		{Path: "docs/specs/core/requirements.v1.json", Content: []byte("requirements\n"), Mode: 0o644},
		{Path: "proofkit/existing.json", Content: []byte("after\n"), Mode: 0o644},
	}
	plan, err := BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(context.Background(), root, plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State != StateApplied || result.AppliedCount != 2 {
		t.Fatalf("Apply() result = %#v", result)
	}
	assertTestFile(t, root, "proofkit/existing.json", "after\n", 0o644)
	assertTestFile(t, root, "docs/specs/core/requirements.v1.json", "requirements\n", 0o644)
	assertNoActiveTransaction(t, root)

	repeated, err := BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	result, err = Apply(context.Background(), root, repeated)
	if err != nil || result.State != StateAlreadySatisfied || result.AppliedCount != 0 {
		t.Fatalf("repeated Apply() = %#v, %v", result, err)
	}
}

func TestApplyRejectsStalePlanBeforeAnyMutation(t *testing.T) {
	root := t.TempDir()
	mustWriteTestFile(t, root, "proofkit/a.json", "before-a\n", 0o644)
	mustWriteTestFile(t, root, "proofkit/b.json", "before-b\n", 0o644)
	plan, err := BuildPlan(context.Background(), root, []Target{
		{Path: "proofkit/a.json", Content: []byte("after-a\n"), Mode: 0o644},
		{Path: "proofkit/b.json", Content: []byte("after-b\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, root, "proofkit/b.json", "concurrent\n", 0o644)
	if _, err := Apply(context.Background(), root, plan); err == nil {
		t.Fatal("Apply() admitted stale plan")
	}
	assertTestFile(t, root, "proofkit/a.json", "before-a\n", 0o644)
	assertTestFile(t, root, "proofkit/b.json", "concurrent\n", 0o644)
	assertNoActiveTransaction(t, root)
}

func TestApplyRejectsStaleUnchangedTargetsBeforeControlMutation(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed=%t", mixed), func(t *testing.T) {
			root := t.TempDir()
			mustWriteTestFile(t, root, "proofkit/unchanged.json", "same\n", 0o644)
			targets := []Target{{Path: "proofkit/unchanged.json", Content: []byte("same\n"), Mode: 0o644}}
			if mixed {
				mustWriteTestFile(t, root, "proofkit/changed.json", "before\n", 0o644)
				targets = append(targets, Target{Path: "proofkit/changed.json", Content: []byte("after\n"), Mode: 0o644})
			}
			plan, err := BuildPlan(context.Background(), root, targets)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteTestFile(t, root, "proofkit/unchanged.json", "stale\n", 0o644)
			if _, err := Apply(context.Background(), root, plan); err == nil {
				t.Fatal("Apply() admitted a stale unchanged target")
			}
			if mixed {
				assertTestFile(t, root, "proofkit/changed.json", "before\n", 0o644)
			}
			if _, err := os.Stat(filepath.Join(root, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale plan created control state: %v", err)
			}
		})
	}
}

func TestApplyFaultAfterFirstPublishRestoresExactBeforeState(t *testing.T) {
	root := t.TempDir()
	mustWriteTestFile(t, root, "proofkit/a.json", "before\n", 0o600)
	plan, err := BuildPlan(context.Background(), root, []Target{
		{Path: "docs/new.json", Content: []byte("created\n"), Mode: 0o644},
		{Path: "proofkit/a.json", Content: []byte("after\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, index int) error {
		if point == faultAfterPublish && index == 1 {
			return errors.New("injected")
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), root, plan)
	if err != nil {
		t.Fatalf("apply() error = %v", err)
	}
	if result.State != StateRolledBack || result.FailureClass != "publication_failed" {
		t.Fatalf("apply() result = %#v", result)
	}
	assertTestFile(t, root, "proofkit/a.json", "before\n", 0o600)
	if _, err := os.Stat(filepath.Join(root, "docs", "new.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created target survived rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created directory survived rollback: %v", err)
	}
	assertNoActiveTransaction(t, root)
}

func TestRecoverResumesOrRollsBackARecordedPrefix(t *testing.T) {
	for _, action := range []string{RecoveryResume, RecoveryRollback} {
		t.Run(action, func(t *testing.T) {
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
			leaveInterruptedPrefix(t, rootPath, plan, 1)
			result, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
			if err != nil {
				t.Fatalf("Recover() error = %v", err)
			}
			wantState := StateApplied
			wantA, wantB := "after-a\n", "after-b\n"
			if action == RecoveryRollback {
				wantState = StateRolledBack
				wantA, wantB = "before-a\n", "before-b\n"
			}
			if result.State != wantState || result.RecoveredBy != action {
				t.Fatalf("Recover() result = %#v", result)
			}
			assertTestFile(t, rootPath, "proofkit/a.json", wantA, 0o644)
			assertTestFile(t, rootPath, "proofkit/b.json", wantB, 0o644)
			assertNoActiveTransaction(t, rootPath)
		})
	}
}

func TestJournalRoundTripPreservesExecutablePlan(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteTestFile(t, rootPath, "proofkit/a.json", "before\n", 0o600)
	plan, err := BuildPlan(context.Background(), rootPath, []Target{
		{Path: "docs/new.json", Content: []byte("created\n"), Mode: 0o644},
		{Path: "proofkit/a.json", Content: []byte("after\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := prepareJournal(root, plan); err != nil {
		t.Fatal(err)
	}
	content, err := readOwnedFile(root, journalPath, MaximumJournalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(`"nonClaims"`)) {
		t.Fatal("recovery journal must not persist presentation-only non-claims")
	}
	loaded, err := loadJournal(root)
	if err != nil {
		t.Fatalf("loadJournal() error = %v", err)
	}
	if loaded.TransactionID != plan.TransactionID || loaded.RootID != plan.RootID || len(loaded.Operations) != len(plan.Operations) {
		t.Fatalf("journal round trip changed plan identity: %#v", loaded)
	}
}

func TestRecoverAttributesOnlyCanonicalPreparingJournalIdentity(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("after\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := stablejson.Marshal(journalValue(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, journalTemp, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	wrongID := "sha256:" + strings.Repeat("0", 64)
	if _, err := Recover(context.Background(), rootPath, wrongID, RecoveryRollback); err == nil || !strings.Contains(err.Error(), "identity does not match") {
		t.Fatalf("Recover(wrong identity) error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, filepath.FromSlash(journalTemp))); err != nil {
		t.Fatalf("wrong identity removed preparing journal: %v", err)
	}
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryRollback)
	if err != nil || result.State != StateRolledBack || result.TransactionID != plan.TransactionID {
		t.Fatalf("Recover(canonical temp) result=%#v err=%v", result, err)
	}
}

func TestRecoverDoesNotInventIdentityForPartialPreparingJournal(t *testing.T) {
	rootPath := t.TempDir()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, journalTemp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	suppliedID := "sha256:" + strings.Repeat("1", 64)
	result, err := Recover(context.Background(), rootPath, suppliedID, RecoveryRollback)
	if err != nil || result.State != StateRolledBack || result.TransactionID != "" || !result.AppliedCountKnown || result.AppliedCount != 0 {
		t.Fatalf("Recover(partial temp) result=%#v err=%v", result, err)
	}
	if result.JSONValue()["transactionId"] != nil {
		t.Fatalf("partial recovery attributed caller identity: %#v", result.JSONValue())
	}
}

func TestRecoverFailsClosedOnAmbiguousTargetVector(t *testing.T) {
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
	leaveInterruptedPrefix(t, rootPath, plan, 1)
	mustWriteTestFile(t, rootPath, "proofkit/b.json", "unknown\n", 0o644)
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if result.State != StateRecoveryRequired || result.FailureClass != "ambiguous_target_state" {
		t.Fatalf("Recover() result = %#v", result)
	}
	assertTestFile(t, rootPath, "proofkit/a.json", "after-a\n", 0o644)
	assertTestFile(t, rootPath, "proofkit/b.json", "unknown\n", 0o644)
	if _, err := os.Stat(filepath.Join(rootPath, filepath.FromSlash(activeDirectory))); err != nil {
		t.Fatalf("recovery state was not retained: %v", err)
	}
}

func TestRecoverRollbackRemovesInterruptedTemporaryBeforeCreatedDirectories(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{
		{Path: "new/nested/record.json", Content: []byte("after\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	temporary := transactionTemporaryPath(plan.TransactionID, 0, plan.Operations[0].Path)
	if err := writeOwnedFile(root, temporary, []byte("partial\n"), 0o600); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryRollback)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateRolledBack || result.RecoveredBy != RecoveryRollback {
		t.Fatalf("Recover() result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(rootPath, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created directory survived recovery: %v", err)
	}
	assertNoActiveTransaction(t, rootPath)
}

func TestRecoverCompletesPartiallyDeletedTerminalTombstone(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteTestFile(t, rootPath, "proofkit/a.json", "before\n", 0o644)
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("after\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 1)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(root, committedMarker); err != nil {
		root.Close()
		t.Fatal(err)
	}
	tombstone, err := archiveTerminal(root, plan, Result{AppliedCount: 1, AppliedCountKnown: true, State: StateApplied, TransactionID: plan.TransactionID})
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	for _, name := range []string{"after-000.bin", "journal.json"} {
		if err := root.Remove(filepath.FromSlash(tombstone + "/" + name)); err != nil {
			root.Close()
			t.Fatal(err)
		}
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateApplied || result.RecoveredBy != RecoveryResume || !result.AppliedCountKnown || result.AppliedCount != 1 {
		t.Fatalf("Recover() tombstone result = %#v", result)
	}
	assertTestFile(t, rootPath, "proofkit/a.json", "after\n", 0o644)
	assertNoPendingTransaction(t, rootPath)
}

func TestRecoverRejectsSecretShapedTransactionBeforeFilesystemAccess(t *testing.T) {
	rootPath := t.TempDir()
	secret := "sk-proj-secret-sentinel"
	result, err := Recover(context.Background(), rootPath, secret, RecoveryRollback)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("Recover() result=%#v error=%v", result, err)
	}
	if encoded := fmt.Sprintf("%#v", result.JSONValue()); strings.Contains(encoded, secret) {
		t.Fatalf("Recover() leaked caller transaction in result: %s", encoded)
	}
	if _, err := os.Stat(filepath.Join(rootPath, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid recovery input touched filesystem: %v", err)
	}
}

func TestRecoverReportsObservedPrefixAfterResumeFailure(t *testing.T) {
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
	leaveInterruptedPrefix(t, rootPath, plan, 0)
	runtime := engine{fault: func(point failurePoint, index int) error {
		if point == faultAfterPublish && index == 1 {
			return errors.New("injected")
		}
		return nil
	}}
	result, err := runtime.recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateRecoveryRequired || !result.AppliedCountKnown || result.AppliedCount != 1 {
		t.Fatalf("recover() result = %#v", result)
	}
}

func TestRecoverRejectsUnknownActiveEntryBeforeMutation(t *testing.T) {
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
	leaveInterruptedPrefix(t, rootPath, plan, 1)
	mustWriteTestFile(t, rootPath, activeDirectory+"/unknown.bin", "unknown\n", 0o600)
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateRecoveryRequired || result.FailureClass != "invalid_control_state" {
		t.Fatalf("Recover() result = %#v", result)
	}
	assertTestFile(t, rootPath, "proofkit/a.json", "after-a\n", 0o644)
	assertTestFile(t, rootPath, "proofkit/b.json", "before-b\n", 0o644)
}

func TestProcessDeathAfterRenameIsRecoverable(t *testing.T) {
	if os.Getenv("PROOFKIT_TRANSACTION_CRASH_HELPER") == "1" {
		runTransactionCrashHelper(t)
		return
	}
	rootPath := t.TempDir()
	mustWriteTestFile(t, rootPath, "proofkit/a.json", "before-a\n", 0o644)
	mustWriteTestFile(t, rootPath, "proofkit/b.json", "before-b\n", 0o644)
	targets := crashHelperTargets()
	plan, err := BuildPlan(context.Background(), rootPath, targets)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestProcessDeathAfterRenameIsRecoverable$")
	command.Env = append(os.Environ(), "PROOFKIT_TRANSACTION_CRASH_HELPER=1", "PROOFKIT_TRANSACTION_CRASH_ROOT="+rootPath)
	err = command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 73 {
		t.Fatalf("crash helper error = %v", err)
	}
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateApplied || !result.AppliedCountKnown || result.AppliedCount != 2 {
		t.Fatalf("Recover() result = %#v", result)
	}
	assertTestFile(t, rootPath, "proofkit/a.json", "after-a\n", 0o644)
	assertTestFile(t, rootPath, "proofkit/b.json", "after-b\n", 0o644)
	assertNoPendingTransaction(t, rootPath)
}

func TestRecoverClosesDirectoryCreationCrashGap(t *testing.T) {
	for _, action := range []string{RecoveryResume, RecoveryRollback} {
		t.Run(action, func(t *testing.T) {
			rootPath := t.TempDir()
			plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "new/target.json", Content: []byte("desired\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareJournal(root, plan); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := stageObjects(root, plan); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := writeMarker(root, readyMarker); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := root.Mkdir("new", 0o700); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := writeOwnedFile(root, directoryOwnershipTempPath(0), []byte("{"), 0o600); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}

			result, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
			if err != nil {
				t.Fatal(err)
			}
			wantState := StateApplied
			if action == RecoveryRollback {
				wantState = StateRolledBack
			}
			if result.State != wantState || result.RecoveredBy != action {
				t.Fatalf("Recover() result=%#v", result)
			}
			if action == RecoveryResume {
				assertTestFile(t, rootPath, "new/target.json", "desired\n", 0o644)
			} else if _, err := os.Stat(filepath.Join(rootPath, "new")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rollback retained crash-created directory: %v", err)
			}
			assertNoPendingTransaction(t, rootPath)
		})
	}
}

func TestRecoverClosesTerminalReceiptPublicationCrashGap(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "proofkit"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 1)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(root, committedMarker); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, activeDirectory+"/"+terminalReceiptTempName, []byte("{"), 0o600); err != nil {
		root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := Recover(context.Background(), rootPath, plan.TransactionID, RecoveryResume)
	if err != nil || result.State != StateApplied || result.TransactionID != plan.TransactionID {
		t.Fatalf("Recover() result=%#v error=%v", result, err)
	}
	assertTestFile(t, rootPath, "proofkit/target.json", "desired\n", 0o644)
	assertNoPendingTransaction(t, rootPath)
}

func TestRecoverClosesMarkerPublicationCrashGaps(t *testing.T) {
	tests := []struct {
		action      string
		marker      string
		published   bool
		wantContent string
		wantState   string
	}{
		{action: RecoveryRollback, marker: readyMarker, wantContent: "before\n", wantState: StateRolledBack},
		{action: RecoveryResume, marker: committedMarker, published: true, wantContent: "after\n", wantState: StateApplied},
		{action: RecoveryRollback, marker: rolledBackMarker, wantContent: "before\n", wantState: StateRolledBack},
	}
	for _, test := range tests {
		t.Run(test.marker, func(t *testing.T) {
			rootPath := t.TempDir()
			mustWriteTestFile(t, rootPath, "proofkit/target.json", "before\n", 0o644)
			plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/target.json", Content: []byte("after\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareJournal(root, plan); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := stageObjects(root, plan); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if test.marker != readyMarker {
				if err := writeMarker(root, readyMarker); err != nil {
					root.Close()
					t.Fatal(err)
				}
			}
			if test.published {
				operation := plan.Operations[0]
				if err := publishContent(root, plan, 0, operation.Before, operation.afterContent, operation.After.Mode); err != nil {
					root.Close()
					t.Fatal(err)
				}
			}
			if err := writeOwnedFile(root, test.marker+".tmp", nil, 0o600); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}

			result, err := Recover(context.Background(), rootPath, plan.TransactionID, test.action)
			if err != nil || result.State != test.wantState {
				t.Fatalf("Recover() result=%#v error=%v", result, err)
			}
			assertTestFile(t, rootPath, "proofkit/target.json", test.wantContent, 0o644)
			assertNoPendingTransaction(t, rootPath)
		})
	}
}

func runTransactionCrashHelper(t *testing.T) {
	rootPath := os.Getenv("PROOFKIT_TRANSACTION_CRASH_ROOT")
	plan, err := BuildPlan(context.Background(), rootPath, crashHelperTargets())
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, index int) error {
		if point == faultAfterPublish && index == 1 {
			os.Exit(73)
		}
		return nil
	}}
	if _, err := runtime.apply(context.Background(), rootPath, plan); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash helper did not terminate")
}

func crashHelperTargets() []Target {
	return []Target{
		{Path: "proofkit/a.json", Content: []byte("after-a\n"), Mode: 0o644},
		{Path: "proofkit/b.json", Content: []byte("after-b\n"), Mode: 0o644},
	}
}

func TestPreparingFailureWithoutActiveStateIsRolledBack(t *testing.T) {
	rootPath := t.TempDir()
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	plan := Plan{RootID: rootID, TransactionID: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	result, err := (engine{}).finishPreparingFailure(root, plan, "journal_prepare_failed")
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateRolledBack || result.FailureClass != "journal_prepare_failed" {
		t.Fatalf("finishPreparingFailure() result = %#v", result)
	}
}

func TestApplyRejectsConcurrentCooperativeWriter(t *testing.T) {
	rootPath := t.TempDir()
	plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "proofkit/a.json", Content: []byte("a\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := Apply(context.Background(), rootPath, plan); !errors.Is(err, ErrBusy) {
		t.Fatalf("Apply() error = %v, want ErrBusy", err)
	}
}

func leaveInterruptedPrefix(t *testing.T, rootPath string, plan Plan, prefix int) {
	t.Helper()
	root, rootID, err := openRepository(rootPath)
	if err != nil || rootID != plan.RootID {
		t.Fatalf("openRepository() = %s, %v", rootID, err)
	}
	defer root.Close()
	lock, err := acquireTransactionLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
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
	changed := changedOperationIndexes(plan)
	for position := 0; position < prefix; position++ {
		operationIndex := changed[position]
		operation := plan.Operations[operationIndex]
		if err := publishContent(root, plan, operationIndex, operation.Before, operation.afterContent, operation.After.Mode); err != nil {
			t.Fatal(err)
		}
	}
}

func assertTestFile(t *testing.T, root, relative, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if string(got) != content {
		t.Fatalf("%s content = %q, want %q", relative, got, content)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("%s mode = %v, %v, want %v", relative, infoMode(info), err, mode)
	}
}

func assertNoActiveTransaction(t *testing.T, root string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(activeDirectory))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active transaction remains: %v", err)
	}
}

func assertNoPendingTransaction(t *testing.T, rootPath string) {
	t.Helper()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pending, err := hasPendingTransactionState(root)
	if err != nil || pending {
		t.Fatalf("pending transaction = %t, %v", pending, err)
	}
}

func infoMode(info os.FileInfo) any {
	if info == nil {
		return nil
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}
