package artifactfile

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadAndRemoveRoundTrip(t *testing.T) {
	root := t.TempDir()
	const path = "artifacts/proofkit/report.json"
	if err := WriteAtomic(root, path, []byte("report\n"), 0o640); err != nil {
		t.Fatalf("WriteAtomic() error = %v", err)
	}
	content, err := ReadBounded(root, path, 64)
	if err != nil {
		t.Fatalf("ReadBounded() error = %v", err)
	}
	if string(content) != "report\n" {
		t.Fatalf("ReadBounded() = %q", content)
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("artifact mode = %04o, want 0640", info.Mode().Perm())
	}
	if err := Remove(root, path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact remains after Remove(): %v", err)
	}
}

func TestReadBoundedRejectsUnrepresentableLimit(t *testing.T) {
	root := t.TempDir()
	if _, err := ReadBounded(root, "artifact.json", math.MaxInt64); err == nil {
		t.Fatal("ReadBounded() admitted a limit whose sentinel byte overflows")
	}
}

func TestOperationsRejectSymlinkComponentsWithoutOutsideMutation(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(t *testing.T, root, outside string)
	}{
		{
			name: "parent outside root",
			setup: func(t *testing.T, root, outside string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(root, "artifacts"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "artifacts", "proofkit")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "parent inside root",
			setup: func(t *testing.T, root, _ string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(root, "artifacts", "alias"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("alias", filepath.Join(root, "artifacts", "proofkit")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			testCase.setup(t, root, outside)
			const path = "artifacts/proofkit/report.json"
			if err := WriteAtomic(root, path, []byte("counterfeit"), 0o644); err == nil {
				t.Fatal("WriteAtomic() admitted a symlink component")
			}
			if _, err := ReadBounded(root, path, 64); err == nil {
				t.Fatal("ReadBounded() admitted a symlink component")
			}
			if err := Remove(root, path); err == nil {
				t.Fatal("Remove() admitted a symlink component")
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("outside directory was mutated: %v", entries)
			}
		})
	}
}

func TestOperationsRejectFinalSymlinkWithoutTargetMutation(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "artifacts", "proofkit")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "report.json")); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "write", run: func() error { return WriteAtomic(root, "artifacts/proofkit/report.json", []byte("counterfeit"), 0o644) }},
		{name: "read", run: func() error { _, err := ReadBounded(root, "artifacts/proofkit/report.json", 64); return err }},
		{name: "remove", run: func() error { return Remove(root, "artifacts/proofkit/report.json") }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); err == nil {
				t.Fatal("operation admitted a final symlink")
			}
		})
	}
	content, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "outside" {
		t.Fatalf("outside target was mutated: %q", content)
	}
}
