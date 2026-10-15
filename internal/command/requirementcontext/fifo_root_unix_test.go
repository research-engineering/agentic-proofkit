//go:build darwin || linux

package requirementcontext

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO repository root must be rejected without waiting for a writer. If the
// composer blocks, the test opens a writer to release it and fails.
func TestComposeRejectsFIFORepositoryRootWithoutWriter(t *testing.T) {
	catalog := map[string]any{
		"schemaVersion":      json.Number("2"),
		"catalogId":          "proofkit.test.fifo-root",
		"specTree":           map[string]any{"path": "tree.json"},
		"requirementSources": []any{map[string]any{"nodeId": "proofkit.test.root", "path": "requirements.json"}},
	}
	for _, route := range []string{"direct", "symlink"} {
		t.Run(route, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, "root")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			selected := fifo
			if route == "symlink" {
				selected = filepath.Join(dir, "alias")
				if err := os.Symlink(fifo, selected); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				_, err := Compose(selected, catalog)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO repository root was admitted")
				}
			case <-time.After(10 * time.Second):
				if writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					writer.Close()
				}
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				t.Fatal("Compose waited for a FIFO writer before rejecting the repository root")
			}
		})
	}
}

// A source replaced by a FIFO after path admission must be rejected by the
// handle checks without waiting for a writer.
func TestReadCatalogSourceRejectsFIFOReplacementWithoutWriter(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	if err := os.WriteFile(source, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	swapped := false
	sourceAdmissionBarrier = func(path string) {
		if path != "source.json" || swapped {
			return
		}
		swapped = true
		if err := os.Rename(source, source+".old"); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(source, 0o600); err != nil {
			t.Error(err)
		}
	}
	defer func() { sourceAdmissionBarrier = nil }()
	done := make(chan error, 1)
	go func() {
		_, _, _, err := readCatalogSource(root, "source.json")
		done <- err
	}()
	select {
	case err := <-done:
		if !swapped {
			t.Fatal("admission barrier did not replace the source")
		}
		if err == nil || err.Error() != "requirement context source changed between path and handle admission" {
			t.Fatalf("readCatalogSource() error = %v, want handle admission rejection", err)
		}
	case <-time.After(10 * time.Second):
		if writer, err := os.OpenFile(source, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			writer.Close()
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		t.Fatal("readCatalogSource waited for a FIFO writer before handle admission")
	}
}
