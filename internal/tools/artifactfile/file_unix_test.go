//go:build darwin || linux

package artifactfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadBoundedRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadBounded(root, "artifact", 64)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadBounded() admitted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("ReadBounded() blocked while opening a FIFO")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO fixture changed: info=%v error=%v", info, err)
	}
}
