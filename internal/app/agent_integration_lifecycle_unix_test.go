//go:build darwin || linux

package app

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func TestIntegrationRecoverBusyCLIIsClassified(t *testing.T) {
	root := t.TempDir()
	plan := integrationLifecycleCLI(t, integrationLifecyclePlanArgs(root, "codex", "install"), 0)
	integrationLifecycleCLI(t, integrationLifecycleApplyArgs(root, "codex", "install", plan), 0)
	tx := plan["transaction"].(map[string]any)["transactionId"].(string)
	directory, err := os.Open(filepath.Join(root, repositorytransaction.ControlDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(directory.Fd()), unix.LOCK_UN)
	receipt := integrationLifecycleCLI(t, []string{"integration", "recover", "--repo-root", root, "--transaction", tx, "--action", "resume"}, 1)
	assertIntegrationLifecycleRoot(t, receipt, false)
	if receipt["state"] != "blocked" || receipt["failureClass"] != "transaction_busy" || receipt["tool"] != nil || receipt["transactionResult"] != nil {
		t.Fatal("busy recovery lost the classified no-effect result")
	}
}
