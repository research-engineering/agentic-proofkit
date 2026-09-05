package repositorytransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReplayAppliedRequiresCurrentNativePlanAndExactRetainedResult(t *testing.T) {
	for _, mutation := range []string{"content", "unsafe-parent"} {
		t.Run("observation/"+mutation, func(t *testing.T) {
			ctx := t.Context()
			root := t.TempDir()
			targets := []Target{{Path: "nested/owned", Content: []byte("managed"), Mode: 0o644}}
			initial, err := BuildPlan(ctx, root, targets)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := Apply(ctx, root, initial); err != nil || result.State != StateApplied {
				t.Fatalf("initial: %#v %v", result, err)
			}
			current, err := BuildPlan(ctx, root, targets)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "unsafe-parent" {
				if err := os.Rename(filepath.Join(root, "nested"), filepath.Join(root, "moved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("moved", filepath.Join(root, "nested")); err != nil {
					t.Fatal(err)
				}
			} else {
				mustWriteTestFile(t, root, "nested/owned", "changed", 0o644)
			}
			before := snapshotTestTree(t, root)
			result, err := ReplayApplied(ctx, root, current, initial.TransactionID)
			if err == nil || result != (Result{}) || errors.Is(err, ErrReplayMismatch) != (mutation == "content") {
				t.Fatalf("observation error classification: %#v %v", result, err)
			}
			if mutation == "unsafe-parent" && !strings.Contains(err.Error(), "symlink or non-directory") {
				t.Fatal("native observation error was erased")
			}
			if !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
				t.Fatal("replay mutated the repository")
			}
		})
	}
	for _, state := range []string{"valid", "stale", "pending", "busy", "wrong-id", "other-desired-state", "legacy-receipt", "descriptive", "changed-plan", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			mustWriteTestFile(t, root, "a", "old", 0o644)
			targets := []Target{{Path: "a", Absent: true}}
			initial, err := BuildPlan(context.Background(), root, targets)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := Apply(context.Background(), root, initial); err != nil || result.State != StateApplied {
				t.Fatalf("initial: %#v %v", result, err)
			}
			current, err := BuildPlan(context.Background(), root, targets)
			if err != nil {
				t.Fatal(err)
			}
			expected := initial.TransactionID
			ctx := context.Background()
			switch state {
			case "stale":
				mustWriteTestFile(t, root, "a", "foreign", 0o644)
			case "pending":
				pending, err := BuildPlan(ctx, root, []Target{{Path: "b", Mode: 0o644, Content: []byte("pending")}})
				if err != nil {
					t.Fatal(err)
				}
				leaveInterruptedPrefix(t, root, pending, 0)
				if historical, err := ReadTerminalResult(ctx, root, initial.TransactionID); err != nil || historical.State != StateApplied {
					t.Fatalf("historical receipt should exist beside pending: %#v %v", historical, err)
				}
			case "busy":
				handle, _, err := openRepository(root)
				if err != nil {
					t.Fatal(err)
				}
				defer handle.Close()
				lock, err := acquireTransactionLock(handle)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.release()
			case "wrong-id":
				expected = "sha256:" + strings.Repeat("f", 64)
			case "other-desired-state":
				current, err = BuildPlan(ctx, root, []Target{{Path: "unrelated", Absent: true}})
				if err != nil {
					t.Fatal(err)
				}
			case "legacy-receipt":
				rewriteTerminalAsLegacy(t, root, terminalTombstonePath(expected, StateApplied))
			case "descriptive":
				current = readmittedConstructionPlan(t, current)
			case "changed-plan":
				current = initial
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			before := snapshotTestTree(t, root)
			result, err := ReplayApplied(ctx, root, current, expected)
			if state == "valid" {
				want := Result{State: StateAlreadySatisfied, AppliedCountKnown: true, TransactionID: expected}
				if err != nil || result != want {
					t.Fatalf("replay: %#v %v", result, err)
				}
			} else if err == nil {
				t.Fatalf("invalid replay passed: %#v", result)
			}
			if state == "pending" && !errors.Is(err, ErrRecoveryRequired) || state == "busy" && !errors.Is(err, ErrBusy) || state == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost precise state: %v", err)
			}
			if !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
				t.Fatal("read-only replay changed repository")
			}
		})
	}
}
