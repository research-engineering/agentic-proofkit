package projectstatus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func TestInspectProjectRetainsOriginalCohortAndStatusIdentity(t *testing.T) {
	root := t.TempDir()
	materializeTestProject(t, root)
	unlistedSource, err := os.ReadFile(filepath.Join(root, "docs/specs/pilot/requirements.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"unlisted-invalid.json": []byte("not JSON"), "unlisted-valid.json": unlistedSource} {
		if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wantProject, expectedPaths, manifestDigest := projectInspectionFixture(t, root)
	before := snapshotProjectTree(t, root)
	reads := map[string]int{}
	var control repositorytransaction.ControlInspection
	dependencies := defaultInspectionDependencies
	dependencies.inspectControl = func(ctx context.Context, lease *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
		observed, err := lease.InspectControlState(ctx)
		control = observed
		return observed, err
	}
	dependencies.readFile = func(ctx context.Context, lease *repositorytransaction.InspectionLease, path string, budget *readBudget) (fileObservation, error) {
		observed, err := readProjectFile(ctx, lease, path, budget)
		if err != nil {
			return fileObservation{}, err
		}
		reads[path]++
		if reads[path] == 2 {
			// Deliberately inconsistent test seam: verification consumes only the
			// state and digest, never a second semantic representation.
			observed.content = []byte("not a JSON record")
		}
		return observed, nil
	}
	inspection, err := inspectProjectWithDependencies(context.Background(), root, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Project == nil || inspection.ManifestContentDigest != manifestDigest || inspection.Status.ProjectState != StateVerificationRequired {
		t.Fatalf("inspection did not retain the captured project: %#v", inspection)
	}
	actual, err := inspection.Project.JSONValue()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, wantProject) {
		t.Fatal("retained project differs from the independently captured original records")
	}
	if len(reads) != len(expectedPaths) {
		t.Fatalf("read %d paths, want exactly %d manifest-owned paths", len(reads), len(expectedPaths))
	}
	for _, path := range expectedPaths {
		if reads[path] != 2 {
			t.Fatalf("path read count=%d, want one capture and one verification", reads[path])
		}
	}
	manifest := wantProject["manifest"].(map[string]any)
	children := []any{}
	for _, raw := range manifest["routes"].([]any) {
		route := raw.(map[string]any)
		children = append(children, map[string]any{
			"artifactKind": route["artifactKind"], "expectedDigest": route["artifactId"],
			"observedDigest": route["artifactId"], "state": "admitted",
		})
	}
	// This is the predecessor identity preimage, not the production projection.
	wantIdentity := map[string]any{
		"children": children, "closureState": "admitted", "schemaVersion": json.Number("1"),
		"manifest":    map[string]any{"contentDigest": manifestDigest, "manifestId": manifest["manifestId"], "state": "admitted"},
		"project":     map[string]any{"projectId": "pilot.project", "state": "admitted"},
		"transaction": map[string]any{"epoch": control.EpochID, "state": "clean", "transactionId": nil},
	}
	encoded, err := json.MarshalIndent(wantIdentity, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	wantID := fmt.Sprintf("sha256:%x", sha256.Sum256(append(encoded, '\n')))
	if inspection.Status.SnapshotID != wantID {
		t.Fatalf("snapshot identity=%s, want predecessor identity=%s", inspection.Status.SnapshotID, wantID)
	}
	status, err := Inspect(context.Background(), root)
	if err != nil || !reflect.DeepEqual(status, inspection.Status) {
		t.Fatalf("legacy status projection differs: %v", err)
	}
	assertProjectTreeUnchanged(t, root, before)
}

func TestInspectProjectDoesNotRetainUnusableRecords(t *testing.T) {
	for _, test := range []struct {
		name  string
		path  string
		state ProjectState
	}{
		{"missing manifest", adoptionmaterialization.ProjectManifestPath, StateUninitialized},
		{"invalid manifest", adoptionmaterialization.ProjectManifestPath, StateBlocked},
		{"missing source", "docs/specs/pilot/requirements.v1.json", StateStale},
		{"invalid source", "docs/specs/pilot/requirements.v1.json", StateStale},
		{"source symlink", "docs/specs/pilot/requirements.v1.json", StateBlocked},
		{"oversized source", "docs/specs/pilot/requirements.v1.json", StateBlocked},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			materializeTestProject(t, root)
			path := filepath.Join(root, filepath.FromSlash(test.path))
			var err error
			switch test.name {
			case "missing manifest", "missing source":
				err = os.Remove(path)
			case "invalid manifest", "invalid source":
				err = os.WriteFile(path, []byte("{}\n"), 0o600)
			case "source symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(filepath.Join(root, "README.md"), path)
				}
			case "oversized source":
				err = os.WriteFile(path, make([]byte, MaximumFileBytes+1), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotProjectTree(t, root)
			inspection, err := InspectProject(context.Background(), root)
			if err != nil || inspection.Project != nil || inspection.Status.ProjectState != test.state {
				t.Fatalf("inspection=%#v error=%v, want %s without project", inspection, err, test.state)
			}
			assertProjectTreeUnchanged(t, root, before)
		})
	}
}

func TestInspectProjectCleanupFailureClearsWholeResult(t *testing.T) {
	root := t.TempDir()
	materializeTestProject(t, root)
	before := snapshotProjectTree(t, root)
	closeCalls := 0
	dependencies := defaultInspectionDependencies
	dependencies.closeLease = func(lease *repositorytransaction.InspectionLease) error {
		closeCalls++
		if err := lease.Close(); err != nil {
			return err
		}
		return errors.New("injected cleanup failure")
	}
	inspection, err := inspectAttempt(context.Background(), root, dependencies)
	assertEmptyInspection(t, inspection)
	if err == nil || !strings.Contains(err.Error(), "cleanup failure") || closeCalls != 1 {
		t.Fatalf("cleanup error=%v calls=%d, want one terminal failure", err, closeCalls)
	}
	assertProjectTreeUnchanged(t, root, before)
}

func assertEmptyInspection(t *testing.T, inspection Inspection) {
	t.Helper()
	if !reflect.DeepEqual(inspection, Inspection{}) {
		t.Fatal("failed inspection retained status, project, or observed digest")
	}
}

func projectInspectionFixture(t *testing.T, root string) (map[string]any, []string, string) {
	t.Helper()
	readRecord := func(path string) (map[string]any, []byte) {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		value, err := admission.DecodeJSON(bytes.NewReader(content), MaximumFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any), content
	}
	manifest, content := readRecord(adoptionmaterialization.ProjectManifestPath)
	paths := []string{adoptionmaterialization.ProjectManifestPath}
	project := map[string]any{"manifest": manifest, "requirementSources": []any{}}
	for _, raw := range manifest["routes"].([]any) {
		route := raw.(map[string]any)
		path := route["path"].(string)
		paths = append(paths, path)
		record, _ := readRecord(path)
		switch route["artifactKind"] {
		case "requirement_source":
			project["requirementSources"] = append(project["requirementSources"].([]any), record)
		case "requirement_proof_binding":
			project["proofBinding"] = record
		case "test_evidence_inventory":
			project["testEvidenceInventory"] = record
		default:
			t.Fatal("unexpected artifact kind in independently authored project fixture")
		}
	}
	return project, paths, fmt.Sprintf("sha256:%x", sha256.Sum256(content))
}
