package projectstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestInspectClassifiesMaterializedProjectWithoutApplicationWrites(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.068153284639677751912209073851318961044240216422390589277786880896123148215480")
	root := t.TempDir()
	before := snapshotProjectTree(t, root)
	status, err := Inspect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	assertProjectTreeUnchanged(t, root, before)
	if status.ProjectState != StateUninitialized || status.NextAction.ActionClass != ActionChooseAdoptionMode {
		t.Fatalf("Inspect() = %#v", status)
	}
	if _, err := os.Stat(filepath.Join(root, repositorytransaction.ControlRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Inspect() created transaction state: %v", err)
	}

	materializeTestProject(t, root)
	before = snapshotProjectTree(t, root)
	status, err = Inspect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	assertProjectTreeUnchanged(t, root, before)
	if status.ProjectState != StateVerificationRequired || status.ProjectID != "pilot.project" || status.ManifestID == "" {
		t.Fatalf("Inspect() = %#v", status)
	}

	sourcePath := filepath.Join(root, "docs", "specs", "pilot", "requirements.v1.json")
	if err := os.WriteFile(sourcePath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before = snapshotProjectTree(t, root)
	status, err = Inspect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	assertProjectTreeUnchanged(t, root, before)
	if status.ProjectState != StateStale || !reflectIssue(status.IssueCodes, IssueChildDigestMismatch) {
		t.Fatalf("Inspect() after drift = %#v", status)
	}
}

type projectTreeEntry struct {
	content    []byte
	mode       fs.FileMode
	route      string
	symlinkRef string
}

func snapshotProjectTree(t *testing.T, root string) []projectTreeEntry {
	t.Helper()
	entries := []projectTreeEntry{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		route, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		snapshot := projectTreeEntry{mode: info.Mode(), route: filepath.ToSlash(route)}
		switch {
		case info.Mode().IsRegular():
			snapshot.content, err = os.ReadFile(path)
		case info.Mode()&fs.ModeSymlink != 0:
			snapshot.symlinkRef, err = os.Readlink(path)
		}
		if err != nil {
			return err
		}
		entries = append(entries, snapshot)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot project tree: %v", err)
	}
	return entries
}

func assertProjectTreeUnchanged(t *testing.T, root string, before []projectTreeEntry) {
	t.Helper()
	after := snapshotProjectTree(t, root)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("project tree changed during inspection:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestInspectRejectsAdmittedChildrenWithInvalidCrossRecordClosure(t *testing.T) {
	root := t.TempDir()
	materializeTestProject(t, root)
	breakMaterializedProjectClosure(t, root)
	status, err := Inspect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if status.ProjectState != StateBlocked || !reflectIssue(status.IssueCodes, IssueClosureInvalid) {
		t.Fatalf("Inspect() = %#v, want blocked closure-invalid status", status)
	}
}

func TestInspectFailsClosedOnSymlinksAndBoundsWithoutDisclosure(t *testing.T) {
	t.Run("manifest symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "proofkit"), 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "private.json")
		if err := os.WriteFile(target, []byte("caller-private-value"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(adoptionmaterialization.ProjectManifestPath))); err != nil {
			t.Fatal(err)
		}
		status, err := Inspect(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if status.ProjectState != StateBlocked || strings.Contains(string(mustStatusJSON(t, status)), "caller-private-value") || strings.Contains(string(mustStatusJSON(t, status)), target) {
			t.Fatalf("Inspect() disclosed symlink data: %#v", status)
		}
	})

	t.Run("oversize manifest", func(t *testing.T) {
		root := t.TempDir()
		manifestPath := filepath.Join(root, filepath.FromSlash(adoptionmaterialization.ProjectManifestPath))
		if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, make([]byte, MaximumFileBytes+1), 0o644); err != nil {
			t.Fatal(err)
		}
		status, err := Inspect(context.Background(), root)
		if err != nil || status.ProjectState != StateBlocked {
			t.Fatalf("Inspect() status=%#v error=%v", status, err)
		}
	})

	t.Run("root symlink", func(t *testing.T) {
		realRoot := t.TempDir()
		alias := filepath.Join(t.TempDir(), "repository")
		if err := os.Symlink(realRoot, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(context.Background(), alias); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("Inspect() error = %v", err)
		}
	})
}

func TestInspectRejectsCaseAliasedCanonicalRoute(t *testing.T) {
	root := t.TempDir()
	materializeTestProject(t, root)
	if err := os.Rename(filepath.Join(root, "docs"), filepath.Join(root, "Docs")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), root); err == nil || !strings.Contains(err.Error(), "record route") || strings.Contains(err.Error(), root) {
		t.Fatalf("Inspect() error = %v, want non-disclosing confinement failure", err)
	}
}

func TestInspectCohortValidationClosesCleanEpochABA(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.069681249039502790550676865624759525498194884189057668377576360433547116631868")
	root := t.TempDir()
	control := repositorytransaction.ControlInspection{
		EpochID: digest.SHA256TextRef("unchanged clean epoch"),
		State:   repositorytransaction.ControlStateClean,
	}
	reads := 0
	dependencies := inspectionDependencies{
		inspectControl: func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
			return control, nil
		},
		readFile: func(context.Context, *repositorytransaction.InspectionLease, string, *readBudget) (fileObservation, error) {
			reads++
			if reads%2 == 1 {
				return fileObservation{state: fileMissing}, nil
			}
			return fileObservation{state: fileInvalid}, nil
		},
	}
	if _, err := inspectWithDependencies(context.Background(), root, dependencies); err == nil || !strings.Contains(err.Error(), "both bounded inspection attempts") {
		t.Fatalf("inspectWithDependencies() error = %v", err)
	}
	if reads != 4 {
		t.Fatalf("read count = %d, want two complete two-pass attempts", reads)
	}
}

func TestInspectCleanupFailureDominatesRetryableSnapshotChange(t *testing.T) {
	controlReads := 0
	closeCalls := 0
	dependencies := inspectionDependencies{
		inspectControl: func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
			controlReads++
			return repositorytransaction.ControlInspection{
				EpochID: digest.SHA256TextRef(fmt.Sprintf("control epoch %d", controlReads)),
				State:   repositorytransaction.ControlStateClean,
			}, nil
		},
		readFile: func(context.Context, *repositorytransaction.InspectionLease, string, *readBudget) (fileObservation, error) {
			return fileObservation{state: fileMissing}, nil
		},
		closeLease: func(lease *repositorytransaction.InspectionLease) error {
			closeCalls++
			if err := lease.Close(); err != nil {
				return err
			}
			return errors.New("injected inspection cleanup failure")
		},
	}
	if _, err := inspectWithDependencies(context.Background(), t.TempDir(), dependencies); err == nil || !strings.Contains(err.Error(), "cleanup failure") || errors.Is(err, errSnapshotChanged) {
		t.Fatalf("inspectWithDependencies() error=%v, want terminal cleanup failure", err)
	}
	if controlReads != 2 || closeCalls != 1 {
		t.Fatalf("control reads=%d close calls=%d, want no retry after cleanup failure", controlReads, closeCalls)
	}
}

func TestReopenedProjectFileCleanupFailureDominatesSnapshotClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file := &cleanupFailingInspectionFile{info: info}
	err = verifyReopenedProjectFile(file, info, info.Size())
	if err == nil || errors.Is(err, errSnapshotChanged) || !strings.Contains(err.Error(), "injected close failure") {
		t.Fatalf("verifyReopenedProjectFile() error=%v, want terminal cleanup failure", err)
	}
}

type cleanupFailingInspectionFile struct {
	info os.FileInfo
}

func (*cleanupFailingInspectionFile) Read([]byte) (int, error) {
	return 0, nil
}

func (file *cleanupFailingInspectionFile) Stat() (os.FileInfo, error) {
	return file.info, nil
}

func (*cleanupFailingInspectionFile) Close() error {
	return errors.New("injected close failure")
}

func TestInspectMapsRecoverableControlState(t *testing.T) {
	transactionID := digest.SHA256TextRef("recoverable transaction")
	control := repositorytransaction.ControlInspection{
		EpochID:       digest.SHA256TextRef("recoverable epoch"),
		State:         repositorytransaction.ControlStateRecoverable,
		TransactionID: transactionID,
	}
	dependencies := inspectionDependencies{
		inspectControl: func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
			return control, nil
		},
		readFile: func(context.Context, *repositorytransaction.InspectionLease, string, *readBudget) (fileObservation, error) {
			t.Fatal("recoverable control state must dominate project-file reads")
			return fileObservation{}, nil
		},
	}
	status, err := inspectWithDependencies(context.Background(), t.TempDir(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if status.ProjectState != StateRecoveryRequired || status.NextAction.ActionClass != ActionChooseRecovery || status.NextAction.ContextRef != transactionID {
		t.Fatalf("inspectWithDependencies() = %#v", status)
	}
}

func TestInspectMapsInvalidControlState(t *testing.T) {
	root := t.TempDir()
	controlDirectory := filepath.Join(root, filepath.FromSlash(repositorytransaction.ControlDirectory))
	if err := os.MkdirAll(controlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controlDirectory, "unknown"), []byte("opaque"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := Inspect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if status.ProjectState != StateBlocked || status.NextAction.ActionClass != ActionRepairControlState || !reflectIssue(status.IssueCodes, IssueTransactionInvalid) {
		t.Fatalf("Inspect()=%#v, want invalid transaction classification", status)
	}
}

func TestInspectAttemptRejectsFinalRepositoryRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	control := repositorytransaction.ControlInspection{EpochID: digest.SHA256TextRef("stable epoch"), State: repositorytransaction.ControlStateClean}
	controlReads := 0
	dependencies := inspectionDependencies{
		inspectControl: func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
			controlReads++
			if controlReads == 2 {
				if err := os.Rename(root, root+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			return control, nil
		},
		readFile: func(context.Context, *repositorytransaction.InspectionLease, string, *readBudget) (fileObservation, error) {
			return fileObservation{state: fileMissing}, nil
		},
	}
	if _, err := inspectAttempt(context.Background(), root, dependencies); !errors.Is(err, repositorytransaction.ErrControlStateChanged) {
		t.Fatalf("inspectAttempt() error=%v, want repository-root change", err)
	}
}

func TestInspectRejectsChangingControlEpochAcrossBothAttempts(t *testing.T) {
	controlReads := 0
	dependencies := inspectionDependencies{
		inspectControl: func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
			controlReads++
			return repositorytransaction.ControlInspection{
				EpochID: digest.SHA256TextRef(fmt.Sprintf("control epoch %d", controlReads%2)),
				State:   repositorytransaction.ControlStateClean,
			}, nil
		},
		readFile: func(context.Context, *repositorytransaction.InspectionLease, string, *readBudget) (fileObservation, error) {
			return fileObservation{state: fileMissing}, nil
		},
	}
	if _, err := inspectWithDependencies(context.Background(), t.TempDir(), dependencies); err == nil || !strings.Contains(err.Error(), "both bounded inspection attempts") {
		t.Fatalf("inspectWithDependencies() error = %v", err)
	}
	if controlReads != 4 {
		t.Fatalf("control read count = %d, want two reads per bounded attempt", controlReads)
	}
}

func TestReadProjectFileEnforcesAggregateBoundBeforeRead(t *testing.T) {
	rootPath := t.TempDir()
	lease, err := repositorytransaction.OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	content := bytes.Repeat([]byte{'a'}, MaximumFileBytes)
	for index := 0; index < 8; index++ {
		name := fmt.Sprintf("record-%d.json", index)
		if err := os.WriteFile(filepath.Join(rootPath, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rootPath, "overflow.json"), []byte{'x'}, 0o644); err != nil {
		t.Fatal(err)
	}
	budget := &readBudget{remaining: MaximumAggregateBytes}
	for index := 0; index < 8; index++ {
		observation, err := readProjectFile(context.Background(), lease, fmt.Sprintf("record-%d.json", index), budget)
		if err != nil || observation.state != fileRead {
			t.Fatalf("read %d state=%s error=%v", index, observation.state, err)
		}
	}
	if budget.remaining != 0 {
		t.Fatalf("remaining aggregate budget = %d", budget.remaining)
	}
	overflow, err := readProjectFile(context.Background(), lease, "overflow.json", budget)
	if err != nil || overflow.state != fileInvalid || len(overflow.content) != 0 || budget.remaining != 0 {
		t.Fatalf("overflow=%#v remaining=%d error=%v", overflow, budget.remaining, err)
	}
}

func TestReadProjectFileRejectsSameByteRouteReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "record.json")
	content := []byte("{\"state\":\"same\"}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	lease, err := repositorytransaction.OpenInspectionLease(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	_, err = readProjectFileWithHook(context.Background(), lease, "record.json", &readBudget{remaining: MaximumAggregateBytes}, func() {
		if renameErr := os.Rename(path, path+".original"); renameErr != nil {
			t.Fatal(renameErr)
		}
		if writeErr := os.WriteFile(path, content, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if !errors.Is(err, errSnapshotChanged) {
		t.Fatalf("readProjectFileWithHook() error=%v, want snapshot change", err)
	}
}

func TestInspectDeduplicatesRepeatedIssueCodes(t *testing.T) {
	root := t.TempDir()
	materializeTestProject(t, root)
	manifestContent, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(adoptionmaterialization.ProjectManifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(manifestContent), MaximumFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := adoptionmaterialization.AdmitManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range manifest.Routes[:2] {
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(route.Path))); err != nil {
			t.Fatal(err)
		}
	}
	status, err := Inspect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if status.ProjectState != StateStale || len(status.IssueCodes) != 1 || status.IssueCodes[0] != IssueChildMissing {
		t.Fatalf("Inspect() issues=%v state=%s, want one missing-record issue", status.IssueCodes, status.ProjectState)
	}
}

func TestOutOfBoundManifestIdentityIsAClassificationNotByteIdentity(t *testing.T) {
	statuses := make([]Status, 0, 2)
	for _, fill := range []byte{'a', 'b'} {
		root := t.TempDir()
		manifestPath := filepath.Join(root, filepath.FromSlash(adoptionmaterialization.ProjectManifestPath))
		if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, bytes.Repeat([]byte{fill}, MaximumFileBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		status, err := Inspect(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		statuses = append(statuses, status)
	}
	if statuses[0].ProjectState != StateBlocked || statuses[0].SnapshotID != statuses[1].SnapshotID || statuses[0].StatusID != statuses[1].StatusID {
		t.Fatalf("out-of-bound classifications differ: %#v %#v", statuses[0], statuses[1])
	}
}

func TestInspectHonorsCancellationBeforeReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inspect(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestInspectHonorsCancellationBetweenBoundedReads(t *testing.T) {
	root := t.TempDir()
	materializeTestProject(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	readCount := 0
	dependencies := defaultInspectionDependencies
	dependencies.readFile = func(ctx context.Context, lease *repositorytransaction.InspectionLease, path string, budget *readBudget) (fileObservation, error) {
		observation, err := readProjectFile(ctx, lease, path, budget)
		if err == nil {
			readCount++
			if readCount == 1 {
				cancel()
			}
		}
		return observation, err
	}
	if _, err := inspectWithDependencies(ctx, root, dependencies); !errors.Is(err, context.Canceled) {
		t.Fatalf("inspectWithDependencies() error = %v, want context cancellation", err)
	}
	if readCount != 1 {
		t.Fatalf("read count=%d, want cancellation before the second bounded read", readCount)
	}
}

func TestInspectHonorsCancellationAfterFinalControlObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	controlReads := 0
	dependencies := defaultInspectionDependencies
	dependencies.inspectControl = func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
		controlReads++
		if controlReads == 2 {
			cancel()
		}
		return repositorytransaction.ControlInspection{
			EpochID: digest.SHA256TextRef("stable control epoch"),
			State:   repositorytransaction.ControlStateClean,
		}, nil
	}
	if _, err := inspectWithDependencies(ctx, t.TempDir(), dependencies); !errors.Is(err, context.Canceled) {
		t.Fatalf("inspectWithDependencies() error = %v, want context cancellation", err)
	}
}

func materializeTestProject(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Pilot\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inventory, err := repositoryinventory.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	sourcePlan, err := adoptionplan.Build(adoptionplan.IntentFresh, inventory, "")
	if err != nil {
		t.Fatal(err)
	}
	nonClaims := []any{"Pilot requirement fixture does not prove rollout."}
	request := map[string]any{
		"schemaVersion": json.Number("1"), "requestKind": adoptionmaterialization.RequestKind,
		"requestId": "pilot.materialization.request", "projectId": "pilot.project", "sourcePlan": sourcePlan.JSONValue(),
		"requirementSources": []any{map[string]any{
			"schemaVersion": json.Number("1"), "sourceId": "pilot.requirements", "specPackagePath": "docs/specs/pilot",
			"overviewPath": "docs/specs/pilot/overview.md", "requirementsPath": "docs/specs/pilot/requirements.v1.json",
			"nonClaims": []any{"Pilot source fixture does not prove production readiness."},
			"requirements": []any{map[string]any{
				"claimLevel": "blocking", "deferral": nil, "invariant": "Pilot materialization preserves admitted requirement meaning.",
				"lifecycle":    map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
				"nonClaimRefs": []any{}, "nonClaims": nonClaims, "ownerId": "pilot.owner",
				"proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "requirementId": "REQ-PILOT-001", "riskClass": "high",
				"updatePolicy": map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": "pilot.owner"},
			}},
		}},
		"requirementProofBinding": map[string]any{
			"path": "proofkit/requirement-bindings.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"), "bindingId": "pilot.bindings",
				"requirements":    []any{map[string]any{"claimLevel": "blocking", "nonClaims": nonClaims, "ownerId": "pilot.owner", "proofState": "witness_backed", "requirementId": "REQ-PILOT-001", "specPath": "docs/specs/pilot/requirements.v1.json"}},
				"bindings":        []any{map[string]any{"commandIds": []any{"pilot.command.test"}, "environmentClasses": []any{"local-go"}, "requirementId": "REQ-PILOT-001", "scenarioId": "pilot.scenario.materialization", "witnessId": "pilot.witness.materialization", "witnessKind": "contract", "witnessPath": "internal/pilot/materialization_test.go"}},
				"witnessCommands": []any{map[string]any{"command": "go test ./internal/pilot", "commandId": "pilot.command.test", "environmentClasses": []any{"local-go"}}},
				"selection":       map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}},
				"nonClaims":       []any{"Pilot binding fixture does not execute witnesses."},
			},
		},
		"testEvidenceInventory": map[string]any{
			"path": "proofkit/test-evidence-inventory.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"), "inventoryId": "pilot.inventory", "authority": "caller_owned_inventory",
				"entries": []any{map[string]any{
					"testId": "pilot.test.materialization", "selector": "go test ./internal/pilot -run TestMaterialization", "sourcePath": "internal/pilot/materialization_test.go", "ownerId": "pilot.owner",
					"evidenceClass": "declared_semantic_falsifier_route", "requirementRefs": []any{"REQ-PILOT-001"}, "ownerInvariantRefs": []any{}, "commandRefs": []any{"pilot.command.test"}, "witnessRefs": []any{"pilot.witness.materialization"},
					"falsifier": map[string]any{"falsifierId": "pilot.falsifier.materialization", "negativeCaseId": "pilot.case.materialization", "wrongImplementationClassId": "pilot.wrong.materialization", "dominanceGroup": "pilot.materialization", "supersedes": []any{}},
					"oracle":    map[string]any{"oracleId": "pilot.oracle.materialization", "oracleKind": "negative_exit_and_diagnostic", "expectedPublicOutcome": "invalid materialization fails closed", "assertionSummary": "A contradictory materialization request is rejected before mutation."},
					"nonClaims": []any{},
				}},
				"nonClaims": []any{"Pilot inventory fixture does not execute native tests."},
			},
		},
		"nonClaims": []any{"Pilot materialization request is test-only."},
	}
	plan, err := adoptionmaterialization.BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, exitCode, err := adoptionmaterialization.Apply(context.Background(), request, root, plan.Transaction.TransactionID, plan.Transaction.DesiredStateID); err != nil || exitCode != 0 {
		t.Fatalf("Apply() exit=%d error=%v", exitCode, err)
	}
}

func reflectIssue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func mustStatusJSON(t *testing.T, status Status) []byte {
	t.Helper()
	content, err := json.Marshal(status.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func breakMaterializedProjectClosure(t *testing.T, root string) {
	t.Helper()
	inventoryPath := filepath.Join(root, "proofkit", "test-evidence-inventory.json")
	inventoryContent, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	inventoryRaw, err := admission.DecodeJSON(bytes.NewReader(inventoryContent), MaximumFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	inventory := inventoryRaw.(map[string]any)
	inventory["entries"].([]any)[0].(map[string]any)["requirementRefs"] = []any{"REQ-PILOT-999"}
	inventoryContent, err = stablejson.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, inventoryContent, 0o600); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(root, filepath.FromSlash(adoptionmaterialization.ProjectManifestPath))
	manifestContent, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := admission.DecodeJSON(bytes.NewReader(manifestContent), MaximumFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestRaw.(map[string]any)
	for _, raw := range manifest["routes"].([]any) {
		route := raw.(map[string]any)
		if route["path"] == "proofkit/test-evidence-inventory.json" {
			route["artifactId"] = digest.SHA256BytesRef(inventoryContent)
		}
	}
	delete(manifest, "manifestId")
	manifestID, err := digest.StableJSONSHA256Ref(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest["manifestId"] = manifestID
	manifestContent, err = stablejson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestContent, 0o600); err != nil {
		t.Fatal(err)
	}
}
