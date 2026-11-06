//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRegistryInputsRefuseFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "artifacts/package/npm-pack.json")
	registry := filepath.Join(root, "artifacts/registry/npm-pack.json")
	for _, path := range []string{candidate, registry} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, path, `[{"name":"@example/cli","version":"1.2.3","filename":"example-cli-1.2.3.tgz","integrity":"sha512-expected","shasum":"abc"}]`)
	}
	for _, test := range []struct {
		path, diagnostic string
		invoke           func(string) error
		parents          bool
	}{
		{"raw-pack.json", "read npm pack report", func(path string) error {
			return capturePackReports(filepath.Join(root, "output.json"), []string{path})
		}, true},
		{"explicit-candidate.json", "read release candidate", func(path string) error { return verifyConsumerLock(path, "unused.json") }, true},
		{"package-lock.json", "read registry consumer lock", func(path string) error { return verifyConsumerLock(candidate, path) }, true},
		{"artifacts/registry/npm-publication-mode.txt", "read npm publication mode", func(string) error { return run(root) }, false},
	} {
		t.Run(test.path, func(t *testing.T) {
			path := filepath.Join(root, test.path)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			operands := []string{path}
			if test.parents {
				operands = append(operands, filepath.Join(path, "input.json"))
			}
			for _, input := range operands {
				result := make(chan error, 1)
				go func() { result <- test.invoke(input) }()
				select {
				case err := <-result:
					if err == nil || !strings.Contains(err.Error(), test.diagnostic) {
						t.Fatalf("input %q admission = %v, want %q", input, err, test.diagnostic)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("registry input %q admission blocked on a FIFO", input)
				}
			}
		})
	}
}
