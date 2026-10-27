//go:build darwin || linux

package rootpath

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeRegularOpeningDoesNotChangeTheExactDirectoryBudget(t *testing.T) {
	directory := t.TempDir()
	for index := range 16_385 {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("f%05d", index)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := OpenRegularFile(root, "f00000")
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(content) != "x" {
		t.Fatalf("native regular read = %q, %v, %v", content, readErr, closeErr)
	}
	if file, err := OpenExactRegularFile(root, "f00000"); file != nil || err == nil || !strings.Contains(err.Error(), "entry limit") {
		if file != nil {
			file.Close()
		}
		t.Fatalf("exact route must retain its independent 16384-entry policy: %v", err)
	}
}

func TestNativeRegularOpeningRetainsNoFollowAndCleanup(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "docs", "record"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, target string }{{"leaf", "docs/record"}, {"parent", "docs"}} {
		if err := os.Symlink(link.target, filepath.Join(directory, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, route := range []string{"leaf", "parent/record", "docs"} {
		if file, err := OpenRegularFile(root, route); file != nil || !errors.Is(err, ErrUnsafeRoute) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("unsafe native route %q = %v", route, err)
		}
	}
	if file, err := OpenRegularFile(root, "missing/record"); file != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing native route = %v", err)
	}
	operations := nativeTraversalOperations()
	operations.closeFile = func(file *os.File) error {
		return errors.Join(file.Close(), errors.New("injected close failure"))
	}
	if file, _, err := openObservedRegularFileWithOperations(root, "docs/record", nil, operations, nativeSpelling); file != nil || !errors.Is(err, ErrTraversalCleanup) {
		t.Fatalf("native traversal must refuse cleanup failure: %v", err)
	}
}
