//go:build darwin || linux

package repositoryinventory

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO repository root must be rejected without waiting for a writer. If the
// scanner blocks, the test opens a writer to release it and fails.
func TestScanRejectsFIFORepositoryRootWithoutWriter(t *testing.T) {
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
				_, err := Scan(context.Background(), selected)
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
				t.Fatal("Scan waited for a FIFO writer before rejecting the repository root")
			}
		})
	}
}
