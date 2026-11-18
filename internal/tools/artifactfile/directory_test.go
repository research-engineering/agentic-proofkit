package artifactfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResetDirectoryRemovesOnlyOwnedContents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	resetDirectoryWrite(t, filepath.Join(root, "artifacts", "package", "nested", "stale"), "old output")
	resetDirectoryWrite(t, filepath.Join(root, "artifacts", "sibling", "sentinel"), "keep sibling")
	resetDirectoryWrite(t, filepath.Join(root, "retained", "sentinel"), "keep internal referent")
	resetDirectoryWrite(t, filepath.Join(outside, "sentinel"), "keep external referent")
	target := filepath.Join(root, "artifacts", "package")
	for name, referent := range map[string]string{
		"outside-directory": outside,
		"outside-file":      filepath.Join(outside, "sentinel"),
		"inside-directory":  "../../retained",
		"dangling":          filepath.Join(outside, "missing"),
		"cycle":             "cycle",
	} {
		if err := os.Symlink(referent, filepath.Join(target, name)); err != nil {
			t.Fatal(err)
		}
	}
	beforeOutside := resetDirectorySnapshot(t, outside)
	beforeSibling := resetDirectorySnapshot(t, filepath.Join(root, "artifacts", "sibling"))
	beforeRetained := resetDirectorySnapshot(t, filepath.Join(root, "retained"))
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(t.TempDir(), "mode-control")
	if err := os.Mkdir(control, 0o755); err != nil {
		t.Fatal(err)
	}
	controlInfo, err := os.Stat(control)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := ResetDirectory(root, "artifacts/package"); err != nil {
			t.Fatalf("ResetDirectory() error = %v", err)
		}
		info, err := os.Lstat(target)
		if err != nil || !info.IsDir() || info.Mode().Perm() != controlInfo.Mode().Perm() {
			t.Fatalf("reset target must be a directory with 0755 subject to umask: %v, %v", info, err)
		}
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 0 {
			t.Fatalf("reset target is not empty: %v, %v", entries, err)
		}
	}
	if !reflect.DeepEqual(beforeOutside, resetDirectorySnapshot(t, outside)) ||
		!reflect.DeepEqual(beforeSibling, resetDirectorySnapshot(t, filepath.Join(root, "artifacts", "sibling"))) ||
		!reflect.DeepEqual(beforeRetained, resetDirectorySnapshot(t, filepath.Join(root, "retained"))) {
		t.Fatal("reset mutated a sibling or a stale symlink referent")
	}
}

func TestResetDirectoryCreatesMissingRoutes(t *testing.T) {
	for _, relativePath := range []string{"dist", "artifacts/package", "artifacts/deep/package"} {
		t.Run(relativePath, func(t *testing.T) {
			root := t.TempDir()
			resetDirectoryWrite(t, filepath.Join(root, "sentinel"), "keep")
			if err := ResetDirectory(root, relativePath); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, filepath.FromSlash(relativePath))
			info, err := os.Lstat(target)
			if err != nil || !info.IsDir() {
				t.Fatalf("missing route was not created: %v, %v", info, err)
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatalf("new directory is not empty: %v, %v", entries, err)
			}
			content, err := os.ReadFile(filepath.Join(root, "sentinel"))
			if err != nil || string(content) != "keep" {
				t.Fatalf("root sentinel changed: %q, %v", content, err)
			}
		})
	}
}

func TestResetDirectoryPreflightRefusesUnsafeRoutesWithoutMutation(t *testing.T) {
	for _, route := range []struct {
		name, entry, target string
	}{
		{"target", "artifacts/package", "artifacts/package"},
		{"ancestor", "artifacts", "artifacts/package"},
		{"deep ancestor", "artifacts/middle", "artifacts/middle/package"},
	} {
		for _, kind := range []string{"external symlink", "internal symlink", "dangling symlink", "file"} {
			t.Run(route.name+"/"+kind, func(t *testing.T) {
				root := t.TempDir()
				outside := t.TempDir()
				resetDirectoryWrite(t, filepath.Join(root, "retained", "package", "sentinel"), "keep internal")
				resetDirectoryWrite(t, filepath.Join(root, "old-report.json"), "prior report")
				resetDirectoryWrite(t, filepath.Join(outside, "package", "sentinel"), "keep outside")
				entry := filepath.Join(root, filepath.FromSlash(route.entry))
				if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
					t.Fatal(err)
				}
				if kind == "file" {
					resetDirectoryWrite(t, entry, "not a directory")
				} else {
					referent := outside
					if kind == "internal symlink" {
						referent = filepath.Join(root, "retained")
					} else if kind == "dangling symlink" {
						referent = filepath.Join(root, "missing")
					}
					if err := os.Symlink(referent, entry); err != nil {
						t.Fatal(err)
					}
				}
				beforeRoot := resetDirectorySnapshot(t, root)
				beforeOutside := resetDirectorySnapshot(t, outside)
				if err := ResetDirectory(root, route.target); err == nil {
					t.Fatal("ResetDirectory() admitted an unsafe route")
				}
				if !reflect.DeepEqual(beforeRoot, resetDirectorySnapshot(t, root)) ||
					!reflect.DeepEqual(beforeOutside, resetDirectorySnapshot(t, outside)) {
					t.Fatal("preflight refusal changed the root or outside sentinel tree")
				}
			})
		}
	}
}

func TestResetDirectoryRejectsNonNormalizedOrNonLocalPaths(t *testing.T) {
	for _, path := range []string{"", ".", "..", "../outside", "/absolute", "./dist", "dist/", "a//b", "a/../dist", "a/./dist", "dist\x00"} {
		t.Run(path, func(t *testing.T) {
			root := t.TempDir()
			resetDirectoryWrite(t, filepath.Join(root, "dist", "sentinel"), "keep old output")
			before := resetDirectorySnapshot(t, root)
			if err := ResetDirectory(root, path); err == nil {
				t.Fatal("ResetDirectory() admitted an invalid path")
			}
			if !reflect.DeepEqual(before, resetDirectorySnapshot(t, root)) {
				t.Fatal("invalid path refusal mutated prior output")
			}
		})
	}
}

func TestResetDirectoryRootSelection(t *testing.T) {
	root := t.TempDir()
	resetDirectoryWrite(t, filepath.Join(root, "dist", "stale"), "old output")
	alias := filepath.Join(t.TempDir(), "selected-root")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := ResetDirectory(alias, "dist"); err != nil {
		t.Fatalf("initial root symlink should be followed: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "dist"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("selected root was not reset: %v, %v", entries, err)
	}
	fileRoot := filepath.Join(t.TempDir(), "file")
	resetDirectoryWrite(t, fileRoot, "not a root")
	missingRoot := filepath.Join(t.TempDir(), "missing")
	for _, invalidRoot := range []string{fileRoot, missingRoot} {
		if err := ResetDirectory(invalidRoot, "dist"); err == nil {
			t.Fatal("ResetDirectory() admitted an unavailable directory root")
		}
	}
	if _, err := os.Lstat(missingRoot); !os.IsNotExist(err) {
		t.Fatalf("missing root was created: %v", err)
	}
}

func resetDirectoryWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func resetDirectorySnapshot(t *testing.T, root string) map[string]struct {
	mode  fs.FileMode
	value string
} {
	t.Helper()
	snapshot := map[string]struct {
		mode  fs.FileMode
		value string
	}{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value := ""
		if info.Mode()&os.ModeSymlink != 0 {
			value, err = os.Readlink(path)
		} else if info.Mode().IsRegular() {
			var content []byte
			content, err = os.ReadFile(path)
			value = string(content)
		}
		if err != nil {
			return err
		}
		snapshot[relativePath] = struct {
			mode  fs.FileMode
			value string
		}{info.Mode(), value}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
