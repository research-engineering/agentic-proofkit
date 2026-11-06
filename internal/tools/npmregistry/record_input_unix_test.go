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

func TestRegistryArgumentsPreserveSymlinkTraversalOrder(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target/sub", filepath.Join(root, "jump")); err != nil {
		t.Fatal(err)
	}
	const pack = `{"name":"@example/cli","version":"1.2.3","filename":"example-cli-1.2.3.tgz","integrity":"sha512-expected","shasum":"abc"}`
	const lock = `{"lockfileVersion":3,"packages":{"":{"dependencies":{"@example/cli":"1.2.3"}},"node_modules/@example/cli":{"version":"1.2.3","resolved":"https://registry.npmjs.org/@example/cli/-/cli-1.2.3.tgz","integrity":"sha512-expected","bin":{"cli":"dist/cli"}}}}`
	for name, content := range map[string]string{"candidate.json": "[" + pack + "]", "lock.json": lock, "raw.json": `{"@example/cli":` + pack + `}`} {
		writeFixture(t, filepath.Join(root, name), content)
		writeFixture(t, filepath.Join(target, name), strings.Replace(content, "sha512-expected", "sha512-selected", 1))
	}
	argument := func(name string) string { return root + "/jump/../" + name }
	candidate, lockPath := filepath.Join(root, "candidate.json"), filepath.Join(root, "lock.json")
	if err := verifyConsumerLock(candidate, lockPath); err != nil {
		t.Fatalf("regular control: %v", err)
	}
	if err := verifyConsumerLock(argument("candidate.json"), argument("lock.json")); err != nil {
		t.Fatalf("selected regular pair: %v", err)
	}
	if verifyConsumerLock(argument("candidate.json"), lockPath) == nil || verifyConsumerLock(candidate, argument("lock.json")) == nil {
		t.Fatal("an argv path selected the lexically cleaned sibling instead of the designated file")
	}
	output := filepath.Join(root, "captured.json")
	if err := capturePackReports(output, []string{argument("raw.json")}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(content), "sha512-selected") || strings.Contains(string(content), "sha512-expected") {
		t.Fatalf("capture did not preserve the selected file identity: %v", err)
	}
}
