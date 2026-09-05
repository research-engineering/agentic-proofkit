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
)

func TestAbsentTargetsDistinguishDeletionEmptyAndUnchanged(t *testing.T) {
	for _, test := range []struct {
		name, before, action, version string
		exists, absent                bool
	}{
		{"missing-absent", "", ActionUnchanged, "2", false, true},
		{"empty-delete", "", ActionDelete, "2", true, true},
		{"text-delete", "old", ActionDelete, "2", true, true},
		{"missing-empty", "", ActionCreate, "1", false, false},
		{"empty-unchanged", "", ActionUnchanged, "1", true, false},
		{"text-to-empty", "old", ActionReplace, "1", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.exists {
				mustWriteTestFile(t, root, "a/target", test.before, 0o644)
			}
			target := Target{Path: "a/target", Absent: test.absent}
			if !target.Absent {
				target.Mode = 0o644
			}
			plan, err := BuildPlan(context.Background(), root, []Target{target})
			if err != nil {
				t.Fatal(err)
			}
			if plan.schemaVersion() != json.Number(test.version) || plan.Operations[0].Action != test.action {
				t.Fatalf("wrong independent action/version: %#v", plan)
			}
			if target.Absent && (plan.Operations[0].After != (Snapshot{}) || len(plan.CreatedDirectories) != 0) {
				t.Fatal("absence gained file metadata or directory creation")
			}
			assertConstructionRejected(t, root, readmittedConstructionPlan(t, plan))
			result, err := Apply(context.Background(), root, plan)
			want := StateApplied
			if test.action == ActionUnchanged {
				want = StateAlreadySatisfied
			}
			if err != nil || result.State != want || result.TransactionID != plan.TransactionID {
				t.Fatalf("apply: %#v %v", result, err)
			}
			if target.Absent {
				assertAbsentTestPath(t, root, target.Path)
			} else {
				assertTestFile(t, root, target.Path, "", 0o644)
			}
			replay, err := Apply(context.Background(), root, plan)
			if err != nil || replay.State != StateAlreadySatisfied {
				t.Fatalf("repeat: %#v %v", replay, err)
			}
		})
	}
}

func TestAbsentTargetRejectsPayloadAndNoncanonicalVersionWithoutMutation(t *testing.T) {
	root := t.TempDir()
	for _, target := range []Target{
		{Absent: true, Path: "a", Content: []byte("forbidden")},
		{Absent: true, Path: "a", Mode: 0o644},
	} {
		before := snapshotTestTree(t, root)
		if _, err := BuildPlan(context.Background(), root, []Target{target}); err == nil {
			t.Fatal("absent target admitted payload")
		}
		if !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
			t.Fatal("invalid absence changed repository")
		}
	}
	for _, absent := range []bool{false, true} {
		target := Target{Path: "a", Absent: absent}
		if !absent {
			target.Mode = 0o644
		}
		plan, err := BuildPlan(context.Background(), root, []Target{target})
		if err != nil {
			t.Fatal(err)
		}
		wire := plan.JSONValue()
		wrong := json.Number("2")
		if absent {
			wrong = "1"
		}
		wire["schemaVersion"] = wrong
		if _, err := AdmitPlanOutput(wire); err == nil || !strings.Contains(err.Error(), "schema") {
			t.Fatalf("wrong version did not reach semantic version predicate: %v", err)
		}
	}
}

func TestMixedAbsentTargetDoesNotRequireOrCreateItsParents(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{
		{Path: "a/b/file", Content: []byte("created"), Mode: 0o644},
		{Path: "a/c/file", Absent: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.CreatedDirectories, []string{"a", "a/b"}) {
		t.Fatalf("wrong directory closure: %v", plan.CreatedDirectories)
	}
	if result, err := Apply(context.Background(), root, plan); err != nil || result.State != StateApplied {
		t.Fatalf("apply: %#v %v", result, err)
	}
	assertAbsentTestPath(t, root, "a/c")
	assertTestFile(t, root, "a/b/file", "created", 0o644)
}

func TestDeleteChecksLastBeforeImageAndPreservesForeignRecreation(t *testing.T) {
	for _, afterDelete := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-unlink", true: "after-unlink"}[afterDelete], func(t *testing.T) {
			root := t.TempDir()
			mustWriteTestFile(t, root, "a", "old", 0o600)
			mustWriteTestFile(t, root, "sibling", "untouched", 0o644)
			plan, err := BuildPlan(context.Background(), root, []Target{{Path: "a", Absent: true}})
			if err != nil {
				t.Fatal(err)
			}
			runtime := engine{fault: func(point failurePoint, index int) error {
				if !afterDelete && point == faultBeforePublish || afterDelete && point == faultAfterPublish {
					mustWriteTestFile(t, root, "a", "foreign", 0o600)
					if afterDelete {
						return errors.New("stop after recreation")
					}
				}
				return nil
			}}
			result, err := runtime.apply(context.Background(), root, plan)
			if err != nil || result.State != StateRecoveryRequired {
				t.Fatalf("foreign conflict: %#v %v", result, err)
			}
			assertTestFile(t, root, "a", "foreign", 0o600)
			assertTestFile(t, root, "sibling", "untouched", 0o644)
		})
	}
}

func assertAbsentTestPath(t *testing.T, root, relative string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected absence of %s: %v", relative, err)
	}
}
