//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

func TestRetainedEvidenceReadersRejectNonRegularPaths(t *testing.T) {
	read := func(root string) map[string]error {
		path := packageartifactrecord.RecordPath
		_, admitted := readAdmittedJSON(root, path)
		_, typed := readTypedJSON[packageJSON](root, path)
		_, digest := fileDigestRef(root, path)
		_, execution := packageartifactrecord.Read(root)
		return map[string]error{"admitted": admitted, "typed": typed, "digest": digest, "execution": execution}
	}
	if args := os.Args; len(args) >= 3 && args[len(args)-2] == "evidence-fifo" {
		for reader, err := range read(args[len(args)-1]) {
			if err == nil {
				t.Errorf("%s reader admitted a FIFO", reader)
			}
		}
		return
	}
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(packageartifactrecord.RecordPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"schemaVersion":1}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	for reader, err := range read(root) {
		if err != nil {
			t.Errorf("%s reader refused regular file: %v", reader, err)
		}
	}
	alias := filepath.Join(t.TempDir(), "foreign.json")
	if err := os.WriteFile(alias, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alias, path); err != nil {
		t.Fatal(err)
	}
	for reader, err := range read(root) {
		if err == nil {
			t.Errorf("%s reader followed a foreign symlink", reader)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRetainedEvidenceReadersRejectNonRegularPaths$", "--", "evidence-fifo", root)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("evidence FIFO subprocess: %v (context: %v)\n%s", err, ctx.Err(), out)
	}
}
