package repositorytransaction

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type constructionTarget struct {
	path, before, after   string
	exists                bool
	beforeMode, afterMode fs.FileMode
}

func buildConstructionPlan(t *testing.T, root string, items []constructionTarget) Plan {
	t.Helper()
	targets := make([]Target, 0, len(items))
	for _, item := range items {
		if item.exists {
			mustWriteTestFile(t, root, item.path, item.before, item.beforeMode)
			if err := os.Chmod(filepath.Join(root, filepath.FromSlash(item.path)), item.beforeMode); err != nil {
				t.Fatal(err)
			}
			assertTestFile(t, root, item.path, item.before, item.beforeMode)
		}
		targets = append(targets, Target{Path: item.path, Content: []byte(item.after), Mode: item.afterMode})
	}
	plan, err := BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func readmittedConstructionPlan(t *testing.T, plan Plan) Plan {
	t.Helper()
	wire, err := stablejson.Marshal(plan.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(wire), MaximumJournalBytes)
	if err != nil {
		t.Fatal(err)
	}
	descriptive, err := AdmitPlanOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := stablejson.Marshal(descriptive.JSONValue())
	if err != nil || !bytes.Equal(wire, reencoded) || descriptive.TransactionID != plan.TransactionID || descriptive.DesiredStateID != plan.DesiredStateID {
		t.Fatalf("wire identity changed: %v", err)
	}
	return descriptive
}

func assertConstructionRejected(t *testing.T, root string, plan Plan) {
	t.Helper()
	before := snapshotTestTree(t, root)
	result, err := Apply(context.Background(), root, plan)
	if err == nil {
		t.Errorf("descriptive or transplanted plan executed: %#v", result)
	}
	if !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
		t.Error("rejected Apply changed target/control tree")
	}
}

func TestPlanConstructionSurvivesOnlyNativeCopies(t *testing.T) {
	cases := []struct {
		name  string
		count int
		items []constructionTarget
	}{
		{"create-empty", 1, []constructionTarget{{path: "new/a", afterMode: 0o644}}},
		{"create-nonempty", 1, []constructionTarget{{path: "new/a", after: "new", afterMode: 0o644}}},
		{"replace-empty-mode", 1, []constructionTarget{{path: "old/a", exists: true, beforeMode: 0o600, afterMode: 0o644}}},
		{"replace-to-empty", 1, []constructionTarget{{path: "old/a", exists: true, before: "old", beforeMode: 0o600, afterMode: 0o644}}},
		{"replace-from-empty", 1, []constructionTarget{{path: "old/a", exists: true, after: "new", beforeMode: 0o600, afterMode: 0o644}}},
		{"replace-nonempty", 1, []constructionTarget{{path: "old/a", exists: true, before: "old", after: "new", beforeMode: 0o600, afterMode: 0o644}}},
		{"unchanged-empty", 0, []constructionTarget{{path: "old/a", exists: true, beforeMode: 0o644, afterMode: 0o644}}},
		{"unchanged-nonempty", 0, []constructionTarget{{path: "old/a", exists: true, before: "same", after: "same", beforeMode: 0o644, afterMode: 0o644}}},
		{"mixed-empty", 2, []constructionTarget{{path: "new/a", afterMode: 0o644}, {path: "old/b", exists: true, beforeMode: 0o600, afterMode: 0o644}, {path: "old/c", exists: true, beforeMode: 0o644, afterMode: 0o644}}},
		{"mixed-bytes", 2, []constructionTarget{{path: "new/a", afterMode: 0o644}, {path: "old/b", exists: true, before: "old", beforeMode: 0o600, afterMode: 0o644}, {path: "old/c", exists: true, before: "same", after: "same", beforeMode: 0o644, afterMode: 0o644}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			plan := buildConstructionPlan(t, root, tc.items)
			descriptive := readmittedConstructionPlan(t, plan)
			assertConstructionRejected(t, root, descriptive)
			copy := clonePlan(plan)
			result, err := Apply(context.Background(), root, copy)
			want := StateApplied
			if tc.count == 0 {
				want = StateAlreadySatisfied
			}
			if err != nil || result.State != want || !result.AppliedCountKnown || result.AppliedCount != tc.count || result.TransactionID != plan.TransactionID {
				t.Fatalf("native: %#v %v", result, err)
			}
			for _, item := range tc.items {
				assertTestFile(t, root, item.path, item.after, item.afterMode)
			}
			assertConstructionRejected(t, root, descriptive)
			for _, candidate := range []Plan{plan, copy} {
				replay, err := Apply(context.Background(), root, candidate)
				if err != nil || replay.State != StateAlreadySatisfied || replay.AppliedCount != 0 || !replay.AppliedCountKnown || replay.TransactionID != plan.TransactionID {
					t.Fatalf("native replay: %#v %v", replay, err)
				}
			}
		})
	}
}

func TestPlanConstructionRejectsPublicFieldTransplant(t *testing.T) {
	for _, sameDesired := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-desired=%t", sameDesired), func(t *testing.T) {
			root := t.TempDir()
			first := constructionTarget{path: "a/one", afterMode: 0o644}
			second := constructionTarget{path: "b/two", afterMode: 0o644}
			if sameDesired {
				first.exists, first.beforeMode = true, 0o600
				second = first
				second.beforeMode = 0o640
			}
			a := buildConstructionPlan(t, root, []constructionTarget{first})
			b := buildConstructionPlan(t, root, []constructionTarget{second})
			if a.TransactionID == b.TransactionID || (a.DesiredStateID == b.DesiredStateID) != sameDesired {
				t.Fatal("transplant does not isolate the declared identity relation")
			}
			descriptiveB := readmittedConstructionPlan(t, b)
			forged := a
			forged.CreatedDirectories = descriptiveB.CreatedDirectories
			forged.DesiredStateID = descriptiveB.DesiredStateID
			forged.Operations = descriptiveB.Operations
			forged.RootID = descriptiveB.RootID
			forged.TransactionID = descriptiveB.TransactionID
			if _, err := AdmitPlanOutput(forged.JSONValue()); err != nil {
				t.Fatalf("transplant not canonical: %v", err)
			}
			assertConstructionRejected(t, root, forged)
			if result, err := Apply(context.Background(), root, b); err != nil || result.State != StateApplied {
				t.Fatalf("native transplant control failed: %#v %v", result, err)
			}
		})
	}
}

func TestPlanConstructionRetainsIndependentExecutionChecks(t *testing.T) {
	for _, defect := range []string{"before-payload", "after-payload", "root", "target-state"} {
		t.Run(defect, func(t *testing.T) {
			root := t.TempDir()
			item := constructionTarget{path: "old/a", exists: true, before: "before", after: "after", beforeMode: 0o600, afterMode: 0o644}
			plan := buildConstructionPlan(t, root, []constructionTarget{item})
			mutated := clonePlan(plan)
			switch defect {
			case "before-payload":
				mutated.Operations[0].beforeContent[0] = 'X'
			case "after-payload":
				mutated.Operations[0].afterContent[0] = 'X'
			case "root":
				assertConstructionRejected(t, t.TempDir(), mutated)
			case "target-state":
				mustWriteTestFile(t, root, item.path, "foreign", item.beforeMode)
			}
			if mutated.constructedTransactionID != mutated.TransactionID {
				t.Fatal("counterexample lost its native construction binding")
			}
			if defect != "root" {
				assertConstructionRejected(t, root, mutated)
			}
			if defect == "target-state" {
				mustWriteTestFile(t, root, item.path, item.before, item.beforeMode)
			}
			result, err := Apply(context.Background(), root, plan)
			if err != nil || result.State != StateApplied || result.AppliedCount != 1 || !result.AppliedCountKnown {
				t.Fatalf("native control failed: %#v %v", result, err)
			}
			assertTestFile(t, root, item.path, item.after, item.afterMode)
		})
	}
}

func constructionRecoveryItems() []constructionTarget {
	return []constructionTarget{
		{path: "new/a", afterMode: 0o644},
		{path: "old/b", exists: true, before: "same", after: "same", beforeMode: 0o644, afterMode: 0o644},
		{path: "old/c", exists: true, beforeMode: 0o600, afterMode: 0o644},
		{path: "old/d", exists: true, before: "old", beforeMode: 0o600, afterMode: 0o644},
		{path: "old/e", exists: true, after: "new", beforeMode: 0o600, afterMode: 0o644},
		{path: "old/f", exists: true, beforeMode: 0o644, afterMode: 0o644},
	}
}

func TestRecoveryDoesNotRequirePublicPlanConstruction(t *testing.T) {
	for _, stage := range []string{"preparing", "staged", "partial", "terminal"} {
		for _, action := range []string{RecoveryResume, RecoveryRollback} {
			if stage == "preparing" && action == RecoveryResume {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s", stage, action), func(t *testing.T) {
				rootPath := t.TempDir()
				items := constructionRecoveryItems()
				plan := buildConstructionPlan(t, rootPath, items)
				if stage == "preparing" {
					root, _, err := openRepository(rootPath)
					if err != nil {
						t.Fatal(err)
					}
					if err := prepareJournal(root, plan); err != nil {
						t.Fatal(err)
					}
					if err := root.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					prefix := 0
					if stage == "partial" {
						prefix = 2
					}
					if stage == "terminal" && action == RecoveryResume {
						prefix = 4
					}
					leaveInterruptedPrefix(t, rootPath, plan, prefix)
					if stage == "terminal" {
						root, _, err := openRepository(rootPath)
						if err != nil {
							t.Fatal(err)
						}
						marker := committedMarker
						if action == RecoveryRollback {
							marker = rolledBackMarker
						}
						if err := writeMarker(root, marker); err != nil {
							t.Fatal(err)
						}
						if err := root.Close(); err != nil {
							t.Fatal(err)
						}
					}
				}
				first, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
				wantState, wantCount := StateApplied, 4
				if action == RecoveryRollback {
					wantState, wantCount = StateRolledBack, 0
				}
				if err != nil || first.State != wantState || first.TransactionID != plan.TransactionID || first.RecoveredBy != action || !first.AppliedCountKnown || first.AppliedCount != wantCount || first.FailureClass != "" {
					t.Fatalf("recover: %#v %v", first, err)
				}
				for _, item := range items {
					if action == RecoveryResume {
						assertTestFile(t, rootPath, item.path, item.after, item.afterMode)
					} else if item.exists {
						assertTestFile(t, rootPath, item.path, item.before, item.beforeMode)
					} else if _, err := os.Lstat(filepath.Join(rootPath, item.path)); !os.IsNotExist(err) {
						t.Fatalf("created target retained: %v", err)
					}
				}
				before := snapshotTestTree(t, rootPath)
				repeated, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
				if err != nil || repeated != first || !reflect.DeepEqual(before, snapshotTestTree(t, rootPath)) {
					t.Fatalf("replay differs: %#v %v", repeated, err)
				}
				assertNoPendingTransaction(t, rootPath)
			})
		}
	}
}
