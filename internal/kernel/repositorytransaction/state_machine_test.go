package repositorytransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesiredStateIdentityIsIndependentOfBeforeSnapshot(t *testing.T) {
	root := t.TempDir()
	targets := []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}}
	mustWriteTestFile(t, root, "proofkit/state.json", "before-one\n", 0o644)
	first, err := BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, root, "proofkit/state.json", "before-two\n", 0o644)
	second, err := BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	if first.DesiredStateID == "" || first.DesiredStateID != second.DesiredStateID {
		t.Fatalf("desired-state identities differ: %q != %q", first.DesiredStateID, second.DesiredStateID)
	}
	if first.TransactionID == second.TransactionID {
		t.Fatal("different before snapshots produced one transaction identity")
	}
	changed, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("other\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if changed.DesiredStateID == first.DesiredStateID {
		t.Fatal("changed final bytes preserved desired-state identity")
	}
	if first.JSONValue()["desiredStateId"] != first.DesiredStateID {
		t.Fatalf("plan projection omitted desired-state identity: %#v", first.JSONValue())
	}
}

func TestApplyAcceptsOriginalPlanAfterLostAcknowledgement(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), root, plan); err != nil || result.State != StateApplied {
		t.Fatalf("first Apply() result=%#v error=%v", result, err)
	}
	result, err := Apply(context.Background(), root, plan)
	if err != nil || result.State != StateAlreadySatisfied || result.TransactionID != plan.TransactionID {
		t.Fatalf("retry Apply() result=%#v error=%v", result, err)
	}
}

func TestApplyCancellationRespectsMutationBoundary(t *testing.T) {
	t.Run("before control state", func(t *testing.T) {
		root := t.TempDir()
		plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Apply(ctx, root, plan); !errors.Is(err, context.Canceled) {
			t.Fatalf("Apply() error=%v, want context cancellation", err)
		}
		if _, err := os.Stat(filepath.Join(root, ControlRoot)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled apply created control state: %v", err)
		}
	})

	t.Run("after ready marker", func(t *testing.T) {
		root := t.TempDir()
		mustWriteTestFile(t, root, "proofkit/state.json", "before\n", 0o644)
		plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		runtime := engine{fault: func(point failurePoint, _ int) error {
			if point == faultAfterReady {
				cancel()
			}
			return nil
		}}
		result, err := runtime.apply(ctx, root, plan)
		if err != nil || result.State != StateRolledBack || result.FailureClass != "cancelled" {
			t.Fatalf("cancelled apply result=%#v error=%v", result, err)
		}
		assertTestFile(t, root, "proofkit/state.json", "before\n", 0o644)
		assertNoPendingTransaction(t, root)
	})
}

func TestRecoverCancellationDoesNotCreateOrRemoveState(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		root := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		transactionID := "sha256:" + strings.Repeat("1", 64)
		if _, err := Recover(ctx, root, transactionID, RecoveryRollback); !errors.Is(err, context.Canceled) {
			t.Fatalf("Recover() error=%v, want context cancellation", err)
		}
		if _, err := os.Stat(filepath.Join(root, ControlRoot)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled recovery created control state: %v", err)
		}
	})

	t.Run("pending", func(t *testing.T) {
		root := t.TempDir()
		plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
		if err != nil {
			t.Fatal(err)
		}
		leaveInterruptedPrefix(t, root, plan, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Recover(ctx, root, plan.TransactionID, RecoveryRollback); !errors.Is(err, context.Canceled) {
			t.Fatalf("Recover() error=%v, want context cancellation", err)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(activeDirectory))); err != nil {
			t.Fatalf("cancelled recovery removed active state: %v", err)
		}
	})
}

func TestPendingErrorCarriesOnlyObservedIdentity(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, root, plan, 0)
	_, err = BuildPlan(context.Background(), root, []Target{{Path: "proofkit/other.json", Content: []byte("other\n"), Mode: 0o644}})
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("BuildPlan() error=%v, want recovery required", err)
	}
	transactionID, ok := RecoveryTransactionID(err)
	if !ok || transactionID != plan.TransactionID {
		t.Fatalf("RecoveryTransactionID()=%q,%t, want %q,true", transactionID, ok, plan.TransactionID)
	}
}

func TestCleanupDurabilityFailureDoesNotClaimRecoverableState(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point == faultAfterStateRemoval {
			return errors.New("injected")
		}
		return nil
	}}
	result, err := runtime.apply(context.Background(), root, plan)
	if err != nil || result.State != StateDurabilityUnknown {
		t.Fatalf("apply() result=%#v error=%v", result, err)
	}
	assertTestFile(t, root, "proofkit/state.json", "desired\n", 0o644)
	assertNoPendingTransaction(t, root)
	replayed, err := Recover(context.Background(), root, plan.TransactionID, RecoveryResume)
	if err != nil || replayed.State != StateApplied || replayed.RecoveredBy != RecoveryResume {
		t.Fatalf("Recover() replay=%#v error=%v", replayed, err)
	}
}

func TestControlNamespaceRequiresPrivateMode(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ControlRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/state.json", Content: []byte("desired\n"), Mode: 0o644}}); err == nil {
		t.Fatal("BuildPlan() admitted a non-private control namespace")
	}
}
