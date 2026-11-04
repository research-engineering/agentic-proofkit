//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNPMArchiveFIFORejectedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	content := npmArchive(t, npmArchiveHeaders())
	writeNPMArtifact(t, root, testNPMTarballName, content)
	path := filepath.Join(root, "artifacts", "package", testNPMTarballName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() {
		done <- validPackRecords(root, "artifacts/package/npm-pack.json", packageJSON{Name: testNPMPackageName, Version: "1.2.3"})
	}()
	select {
	case admitted := <-done:
		if admitted {
			t.Fatal("FIFO admitted as npm archive")
		}
	case <-time.After(time.Second):
		t.Fatal("npm archive admission blocked on FIFO")
	}
}
