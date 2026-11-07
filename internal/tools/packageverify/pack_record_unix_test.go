//go:build darwin || linux

package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVerifierRejectsPackRecordFIFO(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("artifacts/package", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo("artifacts/package/npm-pack.json", 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- runVerifier() }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "read npm pack record: artifact source must be a regular non-symlink file") {
			t.Fatalf("pack record refusal = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("package verifier blocked on a FIFO")
	}
}
