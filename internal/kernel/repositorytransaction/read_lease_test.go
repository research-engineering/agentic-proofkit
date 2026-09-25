package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
)

func TestBuildPlanLiveWriterPrecedesPendingClassification(t *testing.T) {
	for _, state := range []string{"absent-active", "empty-active", "valid-active"} {
		t.Run(state, func(t *testing.T) {
			rootPath := t.TempDir()
			targets := []Target{{Path: "target", Content: []byte("desired"), Mode: 0o644}}
			original, err := BuildPlan(context.Background(), rootPath, targets)
			if err != nil {
				t.Fatal(err)
			}
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			writer, err := acquireTransactionLock(root)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.release()
			switch state {
			case "empty-active":
				err = ensureDirectory(root, activeDirectory, 0o700)
			case "valid-active":
				err = prepareJournal(root, original)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Acquisition is the barrier: the writer cannot release until this read finishes.
			plan, err := BuildPlan(context.Background(), rootPath, targets)
			if !errors.Is(err, ErrBusy) || !reflect.DeepEqual(plan, Plan{}) {
				t.Errorf("live writer: plan=%#v error=%v, want empty plan and busy", plan, err)
			}
			if err := writer.releaseChecked(); err != nil {
				t.Fatal(err)
			}
			plan, err = BuildPlan(context.Background(), rootPath, targets)
			if state == "absent-active" {
				if err != nil || !reflect.DeepEqual(plan.JSONValue(), original.JSONValue()) {
					t.Fatalf("released clean writer changed canonical plan: %v", err)
				}
				return
			}
			id, known := RecoveryTransactionID(err)
			if !errors.Is(err, ErrRecoveryRequired) || !reflect.DeepEqual(plan, Plan{}) || known != (state == "valid-active") || known && id != original.TransactionID {
				t.Fatalf("abandoned writer: plan=%#v error=%v identity=%q known=%v", plan, err, id, known)
			}
		})
	}
}

func TestInspectionLeasesShareAndExcludeWriter(t *testing.T) {
	rootPath := t.TempDir()
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	noChange, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "absent", Absent: true}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenInspectionLease(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("second reader must coexist: %v", err)
	}
	defer second.Close()
	for _, reader := range []*InspectionLease{first, second} {
		writer, err := acquireTransactionLock(root)
		writer.release()
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("writer while reader held: %v", err)
		}
		if _, err := Recover(context.Background(), rootPath, noChange.TransactionID, RecoveryResume); !errors.Is(err, ErrBusy) {
			t.Fatalf("recovery while reader held: %v", err)
		}
		if _, err := ReplayApplied(context.Background(), rootPath, noChange, noChange.TransactionID); !errors.Is(err, ErrBusy) {
			t.Fatalf("replay while reader held: %v", err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := acquireTransactionLock(root)
	if err != nil {
		t.Fatalf("writer after both readers closed: %v", err)
	}
	if err := writer.releaseChecked(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildPlanLiveApplyBarrierThenRetainedJournal(t *testing.T) {
	rootPath := t.TempDir()
	targets := []Target{{Path: "target", Content: []byte("desired"), Mode: 0o644}}
	original, err := BuildPlan(context.Background(), rootPath, targets)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	runtime := engine{fault: func(point failurePoint, _ int) error {
		if point != faultAfterTerminal {
			return nil
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return errors.New("retain journal at writer barrier")
	}}
	var result Result
	var applyErr error
	go func() {
		defer close(done)
		result, applyErr = runtime.apply(ctx, rootPath, original)
	}()
	defer func() { resume(); <-done }()
	select {
	case <-entered:
	case <-done:
		t.Fatalf("apply did not reach barrier: %#v %v", result, applyErr)
	case <-ctx.Done():
		t.Fatal("apply did not reach barrier before deadline")
	}
	if plan, err := BuildPlan(ctx, rootPath, targets); !errors.Is(err, ErrBusy) || !reflect.DeepEqual(plan, Plan{}) {
		t.Fatalf("live apply became plan/recovery: %#v %v", plan, err)
	}
	resume()
	<-done
	if applyErr != nil || result.State != StateCleanupRequired || result.TransactionID != original.TransactionID {
		t.Fatalf("writer did not retain expected journal: %#v %v", result, applyErr)
	}
	plan, err := BuildPlan(context.Background(), rootPath, targets)
	id, known := RecoveryTransactionID(err)
	if !errors.Is(err, ErrRecoveryRequired) || !known || id != original.TransactionID || !reflect.DeepEqual(plan, Plan{}) {
		t.Fatalf("retained journal lost recovery identity: %#v %v", plan, err)
	}
}

func TestBuildPlanMissingNamespaceDoesNotWrite(t *testing.T) {
	for _, controlParent := range []bool{false, true} {
		rootPath := t.TempDir()
		if controlParent {
			if err := os.Mkdir(filepath.Join(rootPath, ControlRoot), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		mustWriteTestFile(t, rootPath, "existing", "before", 0o600)
		before := snapshotTestTree(t, rootPath)
		plan, err := BuildPlan(context.Background(), rootPath, []Target{{Path: "existing", Content: []byte("after"), Mode: 0o644}})
		if err != nil || plan.TransactionID == "" || !reflect.DeepEqual(before, snapshotTestTree(t, rootPath)) {
			t.Fatalf("missing-namespace planning changed repository: %v", err)
		}
	}
}

func TestInspectionLeaseRejectsReplacedControlRoute(t *testing.T) {
	for _, relative := range []string{ControlRoot, ControlDirectory} {
		t.Run(relative, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.MkdirAll(filepath.Join(rootPath, ControlDirectory), 0o700); err != nil {
				t.Fatal(err)
			}
			lease, err := OpenInspectionLease(context.Background(), rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			route := filepath.Join(rootPath, relative)
			if err := os.Rename(route, route+"-saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(rootPath, ControlDirectory), 0o700); err != nil {
				t.Fatal(err)
			}
			if relative == ControlRoot {
				if err := os.Remove(filepath.Join(rootPath, ControlDirectory)); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(route+"-saved", "transactions"), filepath.Join(rootPath, ControlDirectory)); err != nil {
					t.Fatal(err)
				}
			}
			if err := lease.VerifyRootIdentity(); !errors.Is(err, ErrControlStateChanged) {
				t.Fatalf("replaced control route accepted: %v", err)
			}
		})
	}
}

func TestBuildPlanHoldsLeaseThroughCaptureAndClose(t *testing.T) {
	rootPath := t.TempDir()
	targets := []Target{{Path: "target", Content: []byte("desired"), Mode: 0o644}}
	expected, err := BuildPlan(context.Background(), rootPath, targets)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	dependencies := nativePlanDependencies()
	opens, captures, closes := 0, 0, 0
	dependencies.openLease = func(ctx context.Context, path string) (*InspectionLease, error) {
		opens++
		return OpenInspectionLease(ctx, path)
	}
	assertExclusion := func() {
		t.Helper()
		writer, _, err := acquireExistingTransactionLock(root)
		writer.release()
		if !errors.Is(err, ErrBusy) {
			t.Errorf("writer entered read interval: %v", err)
		}
	}
	dependencies.inspectTarget = func(pinned *os.Root, name string, maximum int64) (Snapshot, []byte, error) {
		captures++
		assertExclusion()
		reader, err := OpenInspectionLease(context.Background(), rootPath)
		if err != nil {
			t.Fatalf("reader could not coexist with plan capture: %v", err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		snapshot, content, err := inspectTarget(pinned, name, maximum)
		assertExclusion()
		return snapshot, content, err
	}
	dependencies.closeLease = func(lease *InspectionLease) error {
		closes++
		assertExclusion()
		return lease.Close()
	}
	plan, err := buildPlanWithDependencies(context.Background(), rootPath, targets, dependencies)
	if err != nil || opens != 1 || captures != 1 || closes != 1 || !reflect.DeepEqual(plan.JSONValue(), expected.JSONValue()) {
		t.Fatalf("plan/lease interval changed: opens=%d captures=%d closes=%d error=%v", opens, captures, closes, err)
	}
	writer, _, err := acquireExistingTransactionLock(root)
	if err != nil {
		t.Fatalf("writer after plan close: %v", err)
	}
	if err := writer.releaseChecked(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildPlanSkipsUnlockedPendingAfterAbsentLease(t *testing.T) {
	rootPath := t.TempDir()
	dependencies := nativePlanDependencies()
	opens, captures := 0, 0
	dependencies.openLease = func(ctx context.Context, path string) (*InspectionLease, error) {
		opens++
		lease, err := OpenInspectionLease(ctx, path)
		if err != nil {
			return nil, err
		}
		if lease.controlNamespace || lease.lock != nil {
			lease.Close()
			t.Fatal("absent namespace unexpectedly acquired a lock")
		}
		if err := os.MkdirAll(filepath.Join(path, activeDirectory), 0o700); err != nil {
			lease.Close()
			t.Fatal(err)
		}
		return lease, nil
	}
	dependencies.inspectTarget = func(root *os.Root, name string, maximum int64) (Snapshot, []byte, error) {
		captures++
		return inspectTarget(root, name, maximum)
	}
	plan, err := buildPlanWithDependencies(context.Background(), rootPath, []Target{{Path: "target", Content: []byte("after"), Mode: 0o644}}, dependencies)
	if opens != 1 || captures != 1 || !errors.Is(err, ErrControlStateChanged) || errors.Is(err, ErrRecoveryRequired) || !reflect.DeepEqual(plan, Plan{}) {
		t.Fatalf("unlocked pending state was classified: opens=%d captures=%d plan=%#v error=%v", opens, captures, plan, err)
	}
}

func TestBuildPlanRejectsChangesAtCaptureBarrier(t *testing.T) {
	for _, scenario := range []string{"namespace-appearance", "root-replacement", "control-replacement", "control-parent-replacement", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			rootPath := filepath.Join(t.TempDir(), "repository")
			if err := os.Mkdir(rootPath, 0o700); err != nil {
				t.Fatal(err)
			}
			if scenario != "namespace-appearance" {
				if err := os.MkdirAll(filepath.Join(rootPath, ControlDirectory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			mustWriteTestFile(t, rootPath, "target", "before", 0o644)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dependencies := nativePlanDependencies()
			captures := 0
			dependencies.inspectTarget = func(pinned *os.Root, name string, maximum int64) (Snapshot, []byte, error) {
				captures++
				snapshot, content, err := inspectTarget(pinned, name, maximum)
				if err != nil {
					return snapshot, content, err
				}
				// This callback is a deterministic barrier after the last target read.
				switch scenario {
				case "namespace-appearance":
					err = os.MkdirAll(filepath.Join(rootPath, ControlDirectory, "active"), 0o700)
				case "root-replacement":
					err = os.Rename(rootPath, rootPath+"-saved")
					if err == nil {
						err = os.Mkdir(rootPath, 0o700)
					}
				case "control-replacement", "control-parent-replacement":
					relative := ControlDirectory
					if scenario == "control-parent-replacement" {
						relative = ControlRoot
					}
					route := filepath.Join(rootPath, relative)
					err = os.Rename(route, route+"-saved")
					if err == nil {
						err = os.MkdirAll(filepath.Join(rootPath, ControlDirectory), 0o700)
					}
				case "cancel":
					cancel()
				}
				if err != nil {
					t.Fatal(err)
				}
				return snapshot, content, nil
			}
			plan, err := buildPlanWithDependencies(ctx, rootPath, []Target{{Path: "target", Content: []byte("after"), Mode: 0o644}}, dependencies)
			want := ErrControlStateChanged
			if scenario == "cancel" {
				want = context.Canceled
			}
			if captures != 1 || !errors.Is(err, want) || !reflect.DeepEqual(plan, Plan{}) {
				t.Fatalf("capture drift produced plan: captures=%d plan=%#v error=%v want=%v", captures, plan, err, want)
			}
			if scenario == "cancel" {
				root, _, err := openRepository(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				writer, err := acquireTransactionLock(root)
				if err != nil {
					t.Fatalf("canceled plan retained its lease: %v", err)
				}
				if err := writer.releaseChecked(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestBuildPlanEarlierCleanupPreservesCancellation(t *testing.T) {
	for _, stage := range []string{"admission", "target"} {
		for _, canceled := range []bool{false, true} {
			name := stage + "/cleanup"
			if canceled {
				name += "-and-cancellation"
			}
			t.Run(name, func(t *testing.T) {
				rootPath := t.TempDir()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				dependencies := nativePlanDependencies()
				faults := 0
				failClose := func(root *os.Root) error {
					faults++
					file, err := root.Open(".")
					if err != nil {
						t.Fatal(err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
					if canceled {
						cancel()
					}
					return closeReadResource(file, "planning fixture")
				}
				if stage == "admission" {
					dependencies.openLease = func(ctx context.Context, rootPath string) (*InspectionLease, error) {
						lease, err := OpenInspectionLease(ctx, rootPath)
						if err != nil {
							t.Fatal(err)
						}
						fault := failClose(lease.root)
						if err := lease.Close(); err != nil {
							t.Fatal(err)
						}
						return nil, fault
					}
				} else {
					dependencies.inspectTarget = func(root *os.Root, _ string, _ int64) (Snapshot, []byte, error) {
						return Snapshot{}, nil, failClose(root)
					}
				}
				plan, err := buildPlanWithDependencies(ctx, rootPath, []Target{{Path: "target", Content: []byte("after"), Mode: 0o644}}, dependencies)
				_, recoveryKnown := RecoveryTransactionID(err)
				if faults != 1 || !reflect.DeepEqual(plan, Plan{}) || !errors.Is(err, ErrReadCleanup) || errors.Is(err, context.Canceled) != canceled || errors.Is(err, ErrBusy) || errors.Is(err, ErrRecoveryRequired) || recoveryKnown {
					t.Fatalf("lost operational causes: faults=%d plan=%#v error=%v canceled=%v recoveryKnown=%v", faults, plan, err, canceled, recoveryKnown)
				}
			})
		}
	}
}

func TestBuildPlanTraversalCleanupPreservesCancellation(t *testing.T) {
	for _, stage := range []string{"admission", "target"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/canceled=%t", stage, canceled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				dependencies := nativePlanDependencies()
				calls := 0
				fail := func() error {
					calls++
					if canceled {
						cancel()
					}
					return fmt.Errorf("fixture traversal: %w", rootpath.ErrTraversalCleanup)
				}
				if stage == "admission" {
					dependencies.openLease = func(context.Context, string) (*InspectionLease, error) { return nil, fail() }
				} else {
					dependencies.inspectTarget = func(*os.Root, string, int64) (Snapshot, []byte, error) { return Snapshot{}, nil, fail() }
				}
				plan, err := buildPlanWithDependencies(ctx, t.TempDir(), []Target{{Path: "target", Content: []byte("after"), Mode: 0o644}}, dependencies)
				id, known := RecoveryTransactionID(err)
				if calls != 1 || !reflect.DeepEqual(plan, Plan{}) || !errors.Is(err, rootpath.ErrTraversalCleanup) || errors.Is(err, context.Canceled) != canceled || errors.Is(err, ErrBusy) || errors.Is(err, ErrRecoveryRequired) || id != "" || known {
					t.Fatalf("traversal cleanup classification: calls=%d plan=%#v error=%v id=%q known=%v", calls, plan, err, id, known)
				}
			})
		}
	}
}

func TestBuildPlanCloseFailureInvalidatesPlanAndPreservesCancellation(t *testing.T) {
	for _, scenario := range []string{"success", "cancel", "pending"} {
		t.Run(scenario, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.MkdirAll(filepath.Join(rootPath, ControlDirectory), 0o700); err != nil {
				t.Fatal(err)
			}
			if scenario == "pending" {
				if err := os.Mkdir(filepath.Join(rootPath, activeDirectory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dependencies := nativePlanDependencies()
			closes := 0
			dependencies.closeLease = func(lease *InspectionLease) error {
				closes++
				if scenario == "cancel" {
					cancel()
				}
				if err := lease.lock.directory.Close(); err != nil {
					t.Fatal(err)
				}
				return lease.Close()
			}
			plan, err := buildPlanWithDependencies(ctx, rootPath, []Target{{Path: "target", Content: []byte("after"), Mode: 0o644}}, dependencies)
			if closes != 1 || !errors.Is(err, ErrReadCleanup) || !reflect.DeepEqual(plan, Plan{}) || errors.Is(err, ErrRecoveryRequired) || scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cleanup error became plan/classification: closes=%d plan=%#v error=%v", closes, plan, err)
			}
			lease, err := OpenInspectionLease(context.Background(), rootPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
