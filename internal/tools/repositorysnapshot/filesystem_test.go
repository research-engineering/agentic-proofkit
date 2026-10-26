package repositorysnapshot

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSourceFileAdmitsCompleteBytesAndRejectsNonRegularOrOversize(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, "input"), "complete")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, content, err := ReadSourceFile(root, "input")
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
		info, content, err := ReadSourceFile(root, path)
		if err == nil || info != nil || content != nil {
			t.Fatalf("invalid source %q retained a read: %v, %v, %v", path, info, content, err)
		}
	}
}

func TestOpenedSourceReaderRejectsPrematureEOFAndChangedFile(t *testing.T) {
	for _, fault := range []string{"short", "changed", "identity", "complete"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "input")
			writeFile(t, path, "complete")
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
			info, content, err := readOpenedSourceFile(observed, observedReader{file, reader})
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
