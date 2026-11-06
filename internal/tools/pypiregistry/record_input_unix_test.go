//go:build darwin || linux

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRegistryCandidateReaderRefusesFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	const path = "python-packages.json"
	if err := syscall.Mkfifo(filepath.Join(root, path), 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := readPythonPackageSet(root, path)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "regular non-symlink file") {
			t.Fatalf("candidate admission = %v, want a regular-file refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("candidate admission blocked on a FIFO")
	}
}
