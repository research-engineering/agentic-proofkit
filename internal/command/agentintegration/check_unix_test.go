//go:build darwin || linux

package agentintegration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"golang.org/x/sys/unix"
)

func TestCheckFIFONeverRead(t *testing.T) {
	const helperEnvironment = "PROOFKIT_INTEGRATION_CHECK_FIFO_HELPER"
	if os.Getenv(helperEnvironment) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCheckFIFONeverRead$")
		command.Env = append(os.Environ(), helperEnvironment+"=1")
		if err := command.Run(); err != nil || ctx.Err() != nil {
			t.Fatal("FIFO check failed or blocked beyond its bounded subprocess lifetime")
		}
		return
	}
	root := t.TempDir()
	document := checkTestDocument(t, "codex")
	selected := filepath.Join(root, document.path)
	checkMkdir(t, filepath.Dir(selected))
	if err := unix.Mkfifo(selected, 0o600); err != nil {
		t.Fatal("FIFO fixture creation failed")
	}
	before := checkTree(t, root)
	dependencies := nativeCheckDependencies()
	opens := 0
	dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, error) {
		opens++
		file, err := lease.OpenExactRegularFile(path)
		if file != nil {
			_ = file.Close()
			t.Fatal("FIFO unexpectedly returned an opened regular file")
		}
		return file, err
	}
	result, err := checkWithDependencies(context.Background(), root, document, dependencies)
	if err != nil || result.State() != "invalid" || opens != 2 {
		t.Fatal("FIFO was not classified invalid by both non-reading observations")
	}
	checkUnchanged(t, root, before)
}
