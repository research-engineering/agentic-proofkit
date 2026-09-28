package repositorytransaction

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func caselessTreeIdentities(t *testing.T, root string) map[string]fs.FileInfo {
	t.Helper()
	identities := map[string]fs.FileInfo{}
	err := filepath.WalkDir(root, func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(name)
		if err == nil {
			identities[name] = info
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return identities
}

func assertCaselessTreeUnchanged(t *testing.T, root string, before []testTreeEntry, identities map[string]fs.FileInfo) {
	t.Helper()
	if !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
		t.Fatal("refusal or replay changed actual bytes/modes/routes")
	}
	after := caselessTreeIdentities(t, root)
	if len(after) != len(identities) {
		t.Fatal("refusal or replay changed the identity set")
	}
	for name, identity := range identities {
		if after[name] == nil || !os.SameFile(identity, after[name]) {
			t.Fatal("refusal or replay replaced an actual identity")
		}
	}
}

func seedCaselessControl(fixture *caselessFixture, journal string, preparing bool) error {
	for _, directory := range []string{ControlRoot, ControlDirectory, activeDirectory} {
		if err := fixture.mkdir(directory, 0700); err != nil {
			return err
		}
	}
	name := journalPath
	if preparing {
		name = journalTemp
	}
	if err := fixture.create(name, []byte(journal), 0600); err != nil {
		return err
	}
	return nil
}

// These are new, deliberately inconsistent native snapshots, not rewritten
// predecessor fixtures. The retained record and staged objects are valid.
func testCaselessUnmanagedRefusal(t *testing.T, version, requested, existing, action string, directory, legacyEqual bool) {
	t.Helper()
	rootPath := t.TempDir()
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fixture := newCaselessFixture(rootPath)
	if directory {
		requested += "/entry"
		existing += "/entry"
	}
	if err := fixture.create(existing, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := Plan{RootID: rootID, version: json.Number(version), Operations: []Operation{{
		Path: requested, Action: ActionReplace,
		Before: snapshotForContent([]byte("foreign"), 0600), After: snapshotForContent([]byte("changed"), 0644),
		beforeContent: []byte("foreign"), afterContent: []byte("changed"),
	}}}
	if version == "2" {
		plan.Operations = append(plan.Operations, Operation{Path: "absent", Action: ActionUnchanged})
	}
	sort.Slice(plan.Operations, func(i, j int) bool { return plan.Operations[i].Path < plan.Operations[j].Path })
	plan.DesiredStateID, err = digest.StableJSONSHA256Ref(desiredStateIdentityValue(plan))
	if err != nil {
		t.Fatal(err)
	}
	plan.TransactionID, err = digest.StableJSONSHA256Ref(planIdentityValue(plan))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitJournal(journalValue(plan)); err != nil {
		t.Fatal(err)
	}
	journal, err := stablejson.Marshal(journalValue(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := seedCaselessControl(fixture, string(journal), false); err != nil {
		t.Fatal(err)
	}
	for index, operation := range plan.Operations {
		if operation.Action == ActionUnchanged {
			continue
		}
		if err := fixture.create(beforeObjectPath(index), operation.beforeContent, 0600); err != nil {
			t.Fatal(err)
		}
		if err := fixture.create(afterObjectPath(index), operation.afterContent, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.create(readyMarker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.verifyAll(); err != nil {
		t.Fatal(err)
	}
	retained, err := loadJournal(root)
	if err != nil || retained.TransactionID != plan.TransactionID {
		t.Fatalf("negative control journal admission: %v", err)
	}
	if _, err := loadObjects(root, retained); err != nil {
		t.Fatalf("negative control staging admission: %v", err)
	}
	before := snapshotTestTree(t, rootPath)
	identities := caselessTreeIdentities(t, rootPath)
	inspection, err := InspectControlState(context.Background(), rootPath)
	if err != nil || inspection.State != ControlStateRecoverable || inspection.TransactionID != plan.TransactionID {
		t.Fatalf("negative control identity: %#v %v", inspection, err)
	}
	result, err := Recover(context.Background(), rootPath, plan.TransactionID, action)
	if legacyEqual {
		if !errors.Is(err, rootpath.ErrAmbiguousRoute) || result != (Result{}) {
			t.Fatalf("legacy unmanaged route did not causally reject before effects: %#v %v", result, err)
		}
	} else if err != nil || result.State != StateRecoveryRequired || result.FailureClass != "ambiguous_target_state" || result.TransactionID != plan.TransactionID || result.AppliedCountKnown {
		t.Fatalf("non-representable native before vector was not rejected: %#v %v", result, err)
	}
	assertCaselessTreeUnchanged(t, rootPath, before, identities)
}

func TestCanonicalDialectUnmanagedSplitRoutesRejectBeforeEffects(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		for _, directory := range []bool{false, true} {
			kind := "leaf"
			if directory {
				kind = "parent"
			}
			for _, action := range []string{RecoveryResume, RecoveryRollback} {
				t.Run("v"+version+"/"+kind+"/"+action, func(t *testing.T) {
					testCaselessUnmanagedRefusal(t, version, "\u1fb3\u030a", "\u03b1\u03b9\u030a", action, directory, true)
				})
			}
		}
	}
}
