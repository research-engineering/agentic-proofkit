package repositorytransaction

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestTerminalReceiptDesiredIdentityAdmission(t *testing.T) {
	for _, mutation := range []string{"bound", "legacy", "missing", "malformed", "legacy-extra", "future"} {
		t.Run(mutation, func(t *testing.T) {
			receipt := terminalReceipt{AppliedCount: 1, DesiredStateID: "sha256:" + strings.Repeat("a", 64), State: StateApplied, TransactionID: "sha256:" + strings.Repeat("b", 64)}
			value := terminalReceiptValue(receipt)
			switch mutation {
			case "legacy":
				delete(value, "desiredStateId")
				value["schemaVersion"] = json.Number("1")
				receipt.DesiredStateID = ""
			case "missing":
				delete(value, "desiredStateId")
			case "malformed":
				value["desiredStateId"] = "not-a-digest"
			case "legacy-extra":
				value["schemaVersion"] = json.Number("1")
			case "future":
				value["schemaVersion"] = json.Number("3")
			}
			actual, err := admitTerminalReceipt(value)
			if mutation == "bound" || mutation == "legacy" {
				if err != nil || actual != receipt || !reflect.DeepEqual(terminalReceiptValue(actual), value) {
					t.Fatalf("terminal identity round trip: %v %#v", err, actual)
				}
			} else if err == nil {
				t.Fatal("invalid terminal identity was admitted")
			}
		})
	}
}

func rewriteTerminalAsLegacy(t *testing.T, rootPath, relative string) {
	t.Helper()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt, err := loadTerminalReceipt(root, relative)
	if err != nil {
		t.Fatal(err)
	}
	receipt.DesiredStateID = ""
	content, err := stablejson.Marshal(terminalReceiptValue(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, relative, terminalReceiptName), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyTerminalRecoveryPreservesHistoricalIdentity(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "compacted", true: "pending-compaction"}[partial], func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			plan, err := BuildPlan(ctx, root, []Target{{Path: "owned", Content: []byte("current"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			if partial {
				leaveInterruptedPrefix(t, root, plan, 1)
				handle, _, err := openRepository(root)
				if err != nil {
					t.Fatal(err)
				}
				defer handle.Close()
				if err := writeMarker(handle, committedMarker); err != nil {
					t.Fatal(err)
				}
				if err := ensureTerminalReceipt(handle, plan, Result{AppliedCount: 1, AppliedCountKnown: true, State: StateApplied, TransactionID: plan.TransactionID}); err != nil {
					t.Fatal(err)
				}
				rewriteTerminalAsLegacy(t, root, activeDirectory)
			} else {
				if _, err := Apply(ctx, root, plan); err != nil {
					t.Fatal(err)
				}
				rewriteTerminalAsLegacy(t, root, terminalTombstonePath(plan.TransactionID, StateApplied))
			}
			if result, err := Recover(ctx, root, plan.TransactionID, RecoveryResume); err != nil || result.State != StateApplied {
				t.Fatalf("legacy historical recovery: %#v %v", result, err)
			}
			if result, err := ReadTerminalResult(ctx, root, plan.TransactionID); err != nil || result.State != StateApplied {
				t.Fatalf("legacy historical result: %#v %v", result, err)
			}
			current, err := BuildPlan(ctx, root, []Target{{Path: "owned", Content: []byte("current"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotTestTree(t, root)
			if _, err := ReplayApplied(ctx, root, current, plan.TransactionID); !errors.Is(err, ErrReplayMismatch) {
				t.Fatalf("legacy receipt invented a desired-state association: %v", err)
			}
			if !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
				t.Fatal("legacy replay changed repository state")
			}
			if result, err := Apply(ctx, root, current); err != nil || result.State != StateAlreadySatisfied {
				t.Fatalf("freshly reviewed current plan must remain usable: %#v %v", result, err)
			}
		})
	}
}

func TestBoundTerminalRecoveryCompletesInterruptedArchive(t *testing.T) {
	ctx := context.Background()
	rootPath := t.TempDir()
	plan, err := BuildPlan(ctx, rootPath, []Target{{Path: "owned", Content: []byte("after"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	leaveInterruptedPrefix(t, rootPath, plan, 1)
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeMarker(root, committedMarker); err != nil {
		t.Fatal(err)
	}
	if err := ensureTerminalReceipt(root, plan, Result{AppliedCount: 1, AppliedCountKnown: true, State: StateApplied, TransactionID: plan.TransactionID}); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(ctx, rootPath, plan.TransactionID, RecoveryResume)
	if err != nil || result.State != StateApplied || result.RecoveredBy != RecoveryResume {
		t.Fatalf("bound archive recovery: %#v %v", result, err)
	}
	retained, err := readRetainedTerminalReceipt(root, plan.TransactionID)
	if err != nil || retained.RecoveredBy != "" || retained.DesiredStateID != plan.DesiredStateID {
		t.Fatalf("persisted result was rewritten or identity lost: %#v %v", retained, err)
	}
}
