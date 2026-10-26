package repositorysnapshot

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRegularFileAdmitsCompleteBytesAndRejectsNonRegularOrOversize(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, "input"), "complete")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, content, err := ReadRegularFile(root, "input", maxSourceFileBytes)
	if err != nil || info == nil || string(content) != "complete" || info.Size() != int64(len(content)) {
		t.Fatalf("complete read = %v, %q, %v", info, content, err)
	}
	if err := os.Symlink("input", filepath.Join(directory, "link")); err != nil {
		t.Fatal(err)
	}
	oversize, err := root.Create("oversize")
	if err != nil {
		t.Fatal(err)
	}
	if err := oversize.Truncate(maxSourceFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := oversize.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"link", ".", "../input", "oversize"} {
		info, content, err := ReadRegularFile(root, path, maxSourceFileBytes)
		if err == nil || info != nil || content != nil {
			t.Fatalf("invalid source %q retained a read: %v, %v, %v", path, info, content, err)
		}
	}
}

func TestOpenedRegularReaderRejectsPrematureEOFAndChangedFile(t *testing.T) {
	for _, fault := range []string{"short", "json-prefix", "changed", "identity", "complete"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "input")
			writeFile(t, path, "complete")
			if fault == "json-prefix" {
				writeFile(t, path, `{"ok":true}trailing-invalid`)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			observed, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			var reader io.Reader = file
			switch fault {
			case "short":
				reader = io.LimitReader(file, 1)
			case "json-prefix":
				reader = io.LimitReader(file, int64(len(`{"ok":true}`)))
			case "changed":
				reader = io.MultiReader(readAction(func() {
					if err := os.WriteFile(path, []byte("different"), 0o600); err != nil {
						t.Fatal(err)
					}
				}), file)
			case "identity":
				other := filepath.Join(directory, "other")
				writeFile(t, other, "complete")
				observed, err = os.Stat(other)
				if err != nil {
					t.Fatal(err)
				}
			}
			info, content, err := readOpenedRegularFile(observed, observedReader{file, reader}, maxSourceFileBytes)
			if fault == "complete" {
				if err != nil || info == nil || string(content) != "complete" {
					t.Fatalf("restored read = %v, %q, %v", info, content, err)
				}
			} else if err == nil || info != nil || content != nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("fault %s retained bytes: %v, %q, %v", fault, info, content, err)
			}
		})
	}
}

func TestReadRegularFileHonorsCallerBoundAndEmptyFile(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, "input"), "complete")
	writeFile(t, filepath.Join(directory, "empty"), "")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, limit := range []int64{-1, 0, 7, 1<<63 - 1} {
		info, content, err := ReadRegularFile(root, "input", limit)
		if err == nil || info != nil || content != nil {
			t.Fatalf("limit %d retained a result: %v, %q, %v", limit, info, content, err)
		}
	}
	if _, content, err := ReadRegularFile(root, "input", 8); err != nil || string(content) != "complete" {
		t.Fatalf("exact bound = %q, %v", content, err)
	}
	if _, content, err := ReadRegularFile(root, "empty", 0); err != nil || len(content) != 0 {
		t.Fatalf("empty bounded file = %q, %v", content, err)
	}
}

type observedReader struct {
	*os.File
	reader io.Reader
}

func (r observedReader) Read(buffer []byte) (int, error) { return r.reader.Read(buffer) }

type readAction func()

func (action readAction) Read([]byte) (int, error) {
	action()
	return 0, io.EOF
}
