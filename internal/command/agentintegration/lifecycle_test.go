package agentintegration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func lifecycleWrite(t *testing.T, root, path string, content []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	checkMkdir(t, filepath.Dir(full))
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func lifecyclePair(t *testing.T, root string, document Document) {
	t.Helper()
	baseline, err := currentBaseline(document)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleWrite(t, root, document.path, []byte(document.content))
	lifecycleWrite(t, root, baselinePath(document), baseline)
}

func lifecycleDocuments(t *testing.T, tool string) (Document, Document) {
	t.Helper()
	current, err := Source(tool, sourceCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	previous := checkTestDocument(t, tool)
	if current.content == previous.content || current.identity == previous.identity {
		t.Fatal("version fixtures must differ in consumed invocation contracts")
	}
	return current, previous
}

func TestLifecyclePairRecognition(t *testing.T) {
	for _, tool := range Tools() {
		current, previous := lifecycleDocuments(t, tool)
		for _, fixture := range []struct {
			name     string
			seed     func(*testing.T, string)
			failures [3]string
		}{
			{"absent", func(*testing.T, string) {}, [3]string{"", "not_installed", ""}},
			{"bootstrap only current", func(t *testing.T, root string) { lifecycleWrite(t, root, current.path, []byte(current.content)) }, [3]string{"", "missing_baseline", "missing_baseline"}},
			{"bootstrap only unknown", func(t *testing.T, root string) {
				lifecycleWrite(t, root, current.path, []byte("owner-authored instructions\n"))
			}, [3]string{"unrecognized_bootstrap", "unrecognized_bootstrap", "unrecognized_bootstrap"}},
			{"current pair", func(t *testing.T, root string) { lifecyclePair(t, root, current) }, [3]string{}},
			{"previous pair", func(t *testing.T, root string) { lifecyclePair(t, root, previous) }, [3]string{"update_required", "", ""}},
			{"orphan", func(t *testing.T, root string) {
				lifecyclePair(t, root, current)
				if err := os.Remove(filepath.Join(root, current.path)); err != nil {
					t.Fatal(err)
				}
			}, [3]string{"orphan_baseline", "orphan_baseline", ""}},
			{"edited bootstrap", func(t *testing.T, root string) {
				lifecyclePair(t, root, current)
				lifecycleWrite(t, root, current.path, []byte(current.content+"owner edit\n"))
			}, [3]string{"baseline_mismatch", "baseline_mismatch", "baseline_mismatch"}},
			{"wrong bootstrap mode", func(t *testing.T, root string) {
				lifecyclePair(t, root, current)
				if err := os.Chmod(filepath.Join(root, current.path), 0o600); err != nil {
					t.Fatal(err)
				}
			}, [3]string{"baseline_mismatch", "baseline_mismatch", "baseline_mismatch"}},
			{"wrong baseline mode", func(t *testing.T, root string) {
				lifecyclePair(t, root, current)
				if err := os.Chmod(filepath.Join(root, baselinePath(current)), 0o600); err != nil {
					t.Fatal(err)
				}
			}, [3]string{"invalid_baseline", "invalid_baseline", "invalid_baseline"}},
			{"invalid baseline", func(t *testing.T, root string) {
				lifecyclePair(t, root, current)
				lifecycleWrite(t, root, baselinePath(current), []byte("{}\n"))
			}, [3]string{"invalid_baseline", "invalid_baseline", "invalid_baseline"}},
		} {
			for index, operation := range []string{OperationInstall, OperationUpdate, OperationRemove} {
				t.Run(tool+"/"+fixture.name+"/"+operation, func(t *testing.T) {
					root := t.TempDir()
					fixture.seed(t, root)
					before := checkTree(t, root)
					plan, err := PlanLifecycle(context.Background(), root, current, operation)
					if err != nil || plan.failure != fixture.failures[index] {
						t.Fatalf("recognition failure=%s want=%s error=%v", plan.failure, fixture.failures[index], err)
					}
					if plan.failure == "" {
						if plan.state != "ready" || plan.ExitCode() != 0 || plan.transaction == nil {
							t.Fatal("ready plan is incomplete")
						}
						if _, err := repositorytransaction.AdmitPlanOutput(plan.transaction.JSONValue()); err != nil {
							t.Fatal(err)
						}
					} else if plan.state != "blocked" || plan.ExitCode() != 1 || plan.transaction != nil {
						t.Fatal("conflict exposed an executable plan")
					}
					checkUnchanged(t, root, before)
				})
			}
		}
	}
}

func TestLifecycleBaselineCanonicalAdmission(t *testing.T) {
	document := checkTestDocument(t, "codex")
	canonical, err := currentBaseline(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitBaseline(canonical, document); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown", func(v map[string]any) { v["unknown"] = true }},
		{"kind", func(v map[string]any) { v["kind"] = "other" }},
		{"version", func(v map[string]any) { v["schemaVersion"] = 2 }},
		{"tool", func(v map[string]any) { v["tool"] = "claude" }},
		{"path", func(v map[string]any) { v["targetPath"] = "other.md" }},
		{"count zero", func(v map[string]any) { v["byteCount"] = 0 }},
		{"count string", func(v map[string]any) { v["byteCount"] = "1" }},
		{"count beyond bound", func(v map[string]any) { v["byteCount"] = maximumCheckBytes + 1 }},
		{"digest", func(v map[string]any) { v["contentDigest"] = "sha256:bad" }},
		{"mode", func(v map[string]any) { v["mode"] = "0600" }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			value := map[string]any{}
			if err := json.Unmarshal(canonical, &value); err != nil {
				t.Fatal(err)
			}
			mutation.mutate(value)
			content, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := admitBaseline(append(content, '\n'), document); err == nil {
				t.Fatal("invalid baseline admitted")
			}
		})
	}
	for _, value := range [][]byte{canonical[:len(canonical)-1], append(append([]byte{}, canonical...), '\n'), []byte(strings.Replace(string(canonical), "{", "{\"kind\":\"duplicate\",", 1)), []byte(strings.Repeat(" ", maximumBaselineBytes+1))} {
		if _, err := admitBaseline(value, document); err == nil {
			t.Fatal("noncanonical baseline admitted")
		}
	}
}

func TestLifecycleAppliesReplaysAndPreservesNeighbors(t *testing.T) {
	for _, tool := range Tools() {
		t.Run(tool, func(t *testing.T) {
			root := t.TempDir()
			current, previous := lifecycleDocuments(t, tool)
			lifecycleWrite(t, root, "AGENTS.md", []byte("owner instructions\n"))
			otherTool := "claude"
			if tool == otherTool {
				otherTool = "codex"
			}
			other := checkTestDocument(t, otherTool)
			lifecyclePair(t, root, other)
			protectedBootstrap, err := os.ReadFile(filepath.Join(root, other.path))
			if err != nil {
				t.Fatal(err)
			}
			for index, step := range []struct {
				document  Document
				operation string
			}{{previous, OperationInstall}, {current, OperationUpdate}, {current, OperationRemove}} {
				plan, err := PlanLifecycle(context.Background(), root, step.document, step.operation)
				if err != nil || plan.ExitCode() != 0 || !lifecycleHasChanges(*plan.transaction) {
					t.Fatalf("step %d plan failed: %v", index, err)
				}
				receipt, err := ApplyLifecycle(context.Background(), root, step.document, step.operation, plan.transaction.TransactionID, plan.transaction.DesiredStateID)
				if err != nil || receipt.ExitCode() != 0 || receipt.result.State != repositorytransaction.StateApplied {
					t.Fatalf("step %d apply failed: %v", index, err)
				}
				before := checkTree(t, root)
				replay, err := ApplyLifecycle(context.Background(), root, step.document, step.operation, plan.transaction.TransactionID, plan.transaction.DesiredStateID)
				if err != nil || replay.ExitCode() != 0 || replay.result.State != repositorytransaction.StateAlreadySatisfied || replay.result.TransactionID != plan.transaction.TransactionID {
					t.Fatalf("step %d replay failed: %v", index, err)
				}
				checkUnchanged(t, root, before)
				for _, target := range plan.transaction.Operations {
					content, err := os.ReadFile(filepath.Join(root, target.Path))
					if step.operation == OperationRemove {
						if !os.IsNotExist(err) {
							t.Fatal("remove retained a selected file")
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if target.Path == current.path && string(content) != step.document.content {
						t.Fatal("installed bytes differ from document")
					}
					if target.Path == baselinePath(current) {
						if _, err := admitBaseline(content, step.document); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			otherBytes, err := os.ReadFile(filepath.Join(root, other.path))
			if err != nil || !reflect.DeepEqual(otherBytes, protectedBootstrap) {
				t.Fatal("unselected tool changed")
			}
			instructions, err := os.ReadFile(filepath.Join(root, "AGENTS.md"))
			if err != nil || string(instructions) != "owner instructions\n" {
				t.Fatal("neighbor instructions changed")
			}
		})
	}
}

func TestLifecycleRejectsChangedIdentityAndLocalEdits(t *testing.T) {
	t.Run("native outcome projection", func(t *testing.T) {
		id := "sha256:" + strings.Repeat("a", 64)
		seed := LifecycleReceipt{tool: "codex", operation: OperationInstall, expectedTransactionID: id, expectedDesiredStateID: id}
		operational := errors.New("native observation failed")
		for _, outcome := range []struct {
			err     error
			state   string
			failure string
		}{
			{repositorytransaction.ErrReplayMismatch, "blocked", "transaction_identity_mismatch"},
			{repositorytransaction.ErrBusy, "blocked", "transaction_busy"},
			{&repositorytransaction.RecoveryRequiredError{TransactionID: id}, "recovery_required", "pending_transaction_state"},
			{operational, "", ""},
		} {
			for _, terminalError := range []error{nil, repositorytransaction.ErrReadCleanup, context.Canceled, context.DeadlineExceeded} {
				nativeError := errors.Join(outcome.err, terminalError)
				receipt, err := applyLifecycleResult(seed, repositorytransaction.Result{}, nativeError)
				if terminalError != nil || outcome.err == operational {
					if !errors.Is(err, outcome.err) || terminalError != nil && !errors.Is(err, terminalError) || receipt != (LifecycleReceipt{}) {
						t.Fatalf("operational error became a packet: %#v %v", receipt, err)
					}
				} else if err != nil || receipt.state != outcome.state || receipt.failure != outcome.failure || receipt.expectedTransactionID != id || receipt.expectedDesiredStateID != id {
					t.Fatalf("native classification changed: %#v %v", receipt, err)
				}
			}
		}
	})
	for _, mutation := range []string{"desired", "transaction", "local edit", "baseline edit", "symlink", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			document, previous := lifecycleDocuments(t, "codex")
			lifecyclePair(t, root, previous)
			plan, err := PlanLifecycle(context.Background(), root, document, OperationUpdate)
			if err != nil || plan.ExitCode() != 0 {
				t.Fatal("fixture plan failed")
			}
			tx, desired := plan.transaction.TransactionID, plan.transaction.DesiredStateID
			ctx := context.Background()
			switch mutation {
			case "desired":
				desired = "sha256:" + strings.Repeat("0", 64)
			case "transaction":
				tx = "sha256:" + strings.Repeat("0", 64)
			case "local edit":
				lifecycleWrite(t, root, previous.path, []byte("private local edit\n"))
			case "baseline edit":
				lifecycleWrite(t, root, baselinePath(previous), []byte("{}\n"))
			case "symlink":
				if err := os.Remove(filepath.Join(root, previous.path)); err != nil {
					t.Fatal(err)
				}
				checkSymlink(t, "missing", filepath.Join(root, previous.path))
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			before := checkTree(t, root)
			receipt, err := ApplyLifecycle(ctx, root, document, OperationUpdate, tx, desired)
			if err == nil && receipt.ExitCode() == 0 {
				t.Fatal("changed precondition was accepted")
			}
			if err == nil && strings.Contains(receipt.Text(), "private local edit") {
				t.Fatal("caller content reached output")
			}
			checkUnchanged(t, root, before)
		})
	}
}
