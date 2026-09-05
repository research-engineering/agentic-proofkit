package rootpath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExactEntryExistsRejectsPortableAlias(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "Docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if exists, err := ExactEntryExists(root, ".", "Docs"); err != nil || !exists {
		t.Fatalf("ExactEntryExists(exact) = %v, %v", exists, err)
	}
	if exists, err := ExactEntryExists(root, ".", "docs"); err == nil || exists || !strings.Contains(err.Error(), "ambiguous portable") {
		t.Fatalf("ExactEntryExists(alias) = %v, %v", exists, err)
	}
}

func TestExactEntryExistsPropagatesCleanupFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = exactEntryExistsWithClose(root, ".", "missing", func(file *os.File) error {
		_ = file.Close()
		return errors.New("injected close failure")
	})
	if !errors.Is(err, ErrTraversalCleanup) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("exactEntryExistsWithClose() error=%v, want cleanup failure", err)
	}
}

func TestOpenExactRegularFileDoesNotNormalizeCleanupFailureAsMissing(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	operations := nativeTraversalOperations()
	operations.closeFile = func(file *os.File) error {
		_ = file.Close()
		return errors.New("injected close failure")
	}
	_, err = openExactRegularFileWithOperations(root, "missing.json", nil, operations)
	if !errors.Is(err, ErrTraversalCleanup) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("openExactRegularFileWithOperations() error=%v, want cleanup failure", err)
	}
}

func TestOpenExactRegularFilePinsEveryRouteComponent(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "docs", "record.json"), []byte("canonical\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	file, err := OpenExactRegularFile(root, "docs/record.json")
	if err != nil {
		t.Fatal(err)
	}
	content := make([]byte, len("canonical\n"))
	if _, err := file.Read(content); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil || string(content) != "canonical\n" {
		t.Fatalf("close=%v content=%q", err, content)
	}

	if _, err := OpenExactRegularFile(root, "docs/missing.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing error=%v", err)
	}
}

func TestOpenExactRegularFileRejectsParentSymlinkABA(t *testing.T) {
	rootPath := t.TempDir()
	for _, directory := range []string{"docs", "other"} {
		if err := os.Mkdir(filepath.Join(rootPath, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rootPath, "other", "record.json"), []byte("other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	mutated := false
	_, err = openExactRegularFile(root, "docs/record.json", func(componentIndex int) {
		if componentIndex != 0 || mutated {
			return
		}
		mutated = true
		if renameErr := os.Rename(filepath.Join(rootPath, "docs"), filepath.Join(rootPath, "saved")); renameErr != nil {
			t.Fatal(renameErr)
		}
		if symlinkErr := os.Symlink("other", filepath.Join(rootPath, "docs")); symlinkErr != nil {
			t.Fatal(symlinkErr)
		}
	})
	if !errors.Is(err, ErrRouteChanged) {
		t.Fatalf("parent symlink ABA error=%v, want ErrRouteChanged", err)
	}
}

func TestOpenExactRegularFileRejectsFinalComponentABA(t *testing.T) {
	tests := []struct {
		name    string
		replace func(*testing.T, string)
	}{
		{
			name: "regular replacement",
			replace: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, "record.json"), []byte("replacement\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink replacement",
			replace: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.Symlink("saved.json", filepath.Join(directory, "record.json")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			directory := filepath.Join(rootPath, "docs")
			if err := os.Mkdir(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "record.json"), []byte("canonical\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			mutated := false
			_, err = openExactRegularFile(root, "docs/record.json", func(componentIndex int) {
				if componentIndex != 1 || mutated {
					return
				}
				mutated = true
				if renameErr := os.Rename(filepath.Join(directory, "record.json"), filepath.Join(directory, "saved.json")); renameErr != nil {
					t.Fatal(renameErr)
				}
				test.replace(t, directory)
			})
			if !errors.Is(err, ErrRouteChanged) {
				t.Fatalf("final-component ABA error=%v, want ErrRouteChanged", err)
			}
		})
	}
}

func TestExactEntryExistsDistinguishesMissingEntry(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if exists, err := ExactEntryExists(root, ".", "missing"); err != nil || exists {
		t.Fatalf("ExactEntryExists(missing) = %v, %v", exists, err)
	}
}
