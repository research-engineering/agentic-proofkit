package repositorytransaction

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestBuildPlanIsReadOnlyCanonicalAndContentBound(t *testing.T) {
	root := t.TempDir()
	mustWriteTestFile(t, root, "proofkit/existing.json", "before\n", 0o600)
	mustWriteTestFile(t, root, "proofkit/same.json", "same\n", 0o644)

	plan, err := BuildPlan(context.Background(), root, []Target{
		{Path: "proofkit/new.json", Content: []byte("new\n"), Mode: 0o644},
		{Path: "proofkit/existing.json", Content: []byte("after\n"), Mode: 0o644},
		{Path: "proofkit/same.json", Content: []byte("same\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if got := []string{plan.Operations[0].Path, plan.Operations[1].Path, plan.Operations[2].Path}; strings.Join(got, ",") != "proofkit/existing.json,proofkit/new.json,proofkit/same.json" {
		t.Fatalf("operation order = %v", got)
	}
	if plan.Operations[0].Action != ActionReplace || plan.Operations[1].Action != ActionCreate || plan.Operations[2].Action != ActionUnchanged {
		t.Fatalf("actions = %s, %s, %s", plan.Operations[0].Action, plan.Operations[1].Action, plan.Operations[2].Action)
	}
	if plan.TransactionID == "" || plan.RootID == "" {
		t.Fatalf("plan identities are empty: %#v", plan)
	}
	before, ok := plan.BeforeContent(0)
	if !ok || string(before) != "before\n" {
		t.Fatalf("BeforeContent(0) = %q, %t", before, ok)
	}
	before[0] = 'X'
	again, _ := plan.BeforeContent(0)
	if string(again) != "before\n" {
		t.Fatalf("BeforeContent exposed mutable plan bytes: %q", again)
	}
	if _, ok := plan.BeforeContent(1); ok {
		t.Fatal("BeforeContent reported bytes for a missing target")
	}
	if _, err := os.Stat(filepath.Join(root, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created control state: %v", err)
	}
	changed, err := BuildPlan(context.Background(), root, []Target{
		{Path: "proofkit/existing.json", Content: []byte("different\n"), Mode: 0o644},
		{Path: "proofkit/new.json", Content: []byte("new\n"), Mode: 0o644},
		{Path: "proofkit/same.json", Content: []byte("same\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatalf("BuildPlan(changed) error = %v", err)
	}
	if changed.TransactionID == plan.TransactionID {
		t.Fatal("content change preserved transaction identity")
	}
}

func TestBuildPlanPreservesContextCause(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "cancelled", ctx: cancelledContext(), want: context.Canceled},
		{name: "deadline", ctx: expiredContext(), want: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildPlan(test.ctx, t.TempDir(), []Target{{Path: "proofkit/a.json", Content: []byte("a"), Mode: 0o644}}); !errors.Is(err, test.want) {
				t.Fatalf("BuildPlan() error=%v, want %v", err, test.want)
			}
		})
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	cancel()
	return ctx
}

func TestBuildPlanRejectsUnsafeTargetsAndBounds(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		targets []Target
	}{
		{name: "duplicate", targets: []Target{{Path: "proofkit/a.json", Content: []byte("a"), Mode: 0o644}, {Path: "proofkit/a.json", Content: []byte("b"), Mode: 0o644}}},
		{name: "ancestor collision", targets: []Target{{Path: "a", Content: []byte("a"), Mode: 0o644}, {Path: "a/b", Content: []byte("b"), Mode: 0o644}}},
		{name: "control overlap", targets: []Target{{Path: ControlDirectory + "/payload", Content: []byte("a"), Mode: 0o644}}},
		{name: "control ancestor", targets: []Target{{Path: ".agentic-proofkit", Content: []byte("a"), Mode: 0o644}}},
		{name: "control sibling", targets: []Target{{Path: ".agentic-proofkit/config", Content: []byte("a"), Mode: 0o644}}},
		{name: "control case alias", targets: []Target{{Path: ".AGENTIC-PROOFKIT/transactions/payload", Content: []byte("a"), Mode: 0o644}}},
		{name: "case alias", targets: []Target{{Path: "proofkit/A.json", Content: []byte("a"), Mode: 0o644}, {Path: "proofkit/a.json", Content: []byte("b"), Mode: 0o644}}},
		{name: "case alias in parent prefixes", targets: []Target{{Path: "Proofkit/a.json", Content: []byte("a"), Mode: 0o644}, {Path: "proofkit/b.json", Content: []byte("b"), Mode: 0o644}}},
		{name: "unicode normalization alias", targets: []Target{{Path: "proofkit/caf\u00e9.json", Content: []byte("a"), Mode: 0o644}, {Path: "proofkit/cafe\u0301.json", Content: []byte("b"), Mode: 0o644}}},
		{name: "path byte limit", targets: []Target{{Path: strings.Repeat("a", 1025), Content: []byte("a"), Mode: 0o644}}},
		{name: "path component limit", targets: []Target{{Path: strings.Repeat("a/", 64) + "a", Content: []byte("a"), Mode: 0o644}}},
		{name: "parent symlink", targets: []Target{{Path: "linked/a.json", Content: []byte("a"), Mode: 0o644}}},
		{name: "oversize", targets: []Target{{Path: "proofkit/a.json", Content: make([]byte, MaximumFileBytes+1), Mode: 0o644}}},
		{name: "invalid mode", targets: []Target{{Path: "proofkit/a.json", Content: []byte("a"), Mode: 0}}},
		{name: "unreadable mode", targets: []Target{{Path: "proofkit/a.json", Content: []byte("a"), Mode: 0o200}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildPlan(context.Background(), root, test.targets); err == nil {
				t.Fatal("BuildPlan() admitted unsafe targets")
			}
		})
	}
}

func TestApplyRejectsMutatedPlanBeforeControlMutation(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*Plan)
	}{
		{name: "unknown action", mutate: func(plan *Plan) { plan.Operations[0].Action = "unknown" }},
		{name: "unsafe path", mutate: func(plan *Plan) { plan.Operations[0].Path = "../outside" }},
		{name: "unowned directory", mutate: func(plan *Plan) { plan.CreatedDirectories = []string{"unrelated"} }},
		{name: "unreadable mode", mutate: func(plan *Plan) { plan.Operations[0].After.Mode = 0o200 }},
		{name: "setuid mode", mutate: func(plan *Plan) { plan.Operations[0].After.Mode |= fs.ModeSetuid }},
		{name: "setgid mode", mutate: func(plan *Plan) { plan.Operations[0].After.Mode |= fs.ModeSetgid }},
		{name: "sticky mode", mutate: func(plan *Plan) { plan.Operations[0].After.Mode |= fs.ModeSticky }},
		{name: "directory mode", mutate: func(plan *Plan) { plan.Operations[0].After.Mode |= fs.ModeDir }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/a.json", Content: []byte("after\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&plan)
			plan.TransactionID, err = digest.StableJSONSHA256Ref(planIdentityValue(plan))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(context.Background(), root, plan); err == nil {
				t.Fatal("Apply() admitted mutated plan")
			}
			if _, err := os.Stat(filepath.Join(root, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mutated plan created control state: %v", err)
			}
		})
	}
}

func TestApplyRejectsForgedCreatedDirectoryOwnership(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		prepare     func(string)
		directories []string
	}{
		{
			name:   "pre-existing parent",
			target: "proofkit/a.json",
			prepare: func(root string) {
				if err := os.Mkdir(filepath.Join(root, "proofkit"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			directories: []string{"proofkit"},
		},
		{name: "missing required descendant", target: "docs/specs/a.json", prepare: func(string) {}, directories: []string{"docs"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.prepare(root)
			plan, err := BuildPlan(context.Background(), root, []Target{{Path: test.target, Content: []byte("after\n"), Mode: 0o644}})
			if err != nil {
				t.Fatal(err)
			}
			plan.CreatedDirectories = test.directories
			plan.TransactionID, err = digest.StableJSONSHA256Ref(planIdentityValue(plan))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(context.Background(), root, plan); err == nil {
				t.Fatal("Apply() admitted forged created-directory ownership")
			}
			if _, err := os.Stat(filepath.Join(root, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("forged plan created control state: %v", err)
			}
			if test.name == "pre-existing parent" {
				info, err := os.Stat(filepath.Join(root, "proofkit"))
				if err != nil || !info.IsDir() {
					t.Fatalf("pre-existing directory was removed: %v", err)
				}
			}
		})
	}
}

func TestBuildPlanRejectsFinalSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proofkit"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "proofkit", "target.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/target.json", Content: []byte("after\n"), Mode: 0o644}}); err == nil {
		t.Fatal("BuildPlan() admitted a symlink target")
	}
}

func mustWriteTestFile(t *testing.T, root, relative, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
