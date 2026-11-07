//go:build darwin || linux

package releasechange

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadBoundsChangeRecordBeforeDecode(t *testing.T) {
	root := t.TempDir()
	const name = "change.json"
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, make([]byte, maxRecordBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrom(root, name); err == nil || !strings.Contains(err.Error(), "resource limit") {
		t.Fatalf("oversized record = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := Read(path); result <- err }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "regular non-symlink file") {
			t.Fatalf("FIFO record = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("change record read blocked on a FIFO")
	}
}
