//go:build darwin || linux

package app

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func TestIntegrationPlanLiveWriterThenAbandonedRecoveryCLI(t *testing.T) {
	for _, phase := range []string{"preparing-temp", "preparing", "ready"} {
		t.Run(phase, func(t *testing.T) {
			root, transaction, _ := recoveryCLIFixture(t, phase)
			before := recoveryCLITree(t, root)
			directory, err := os.Open(filepath.Join(root, repositorytransaction.ControlDirectory))
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			defer unix.Flock(int(directory.Fd()), unix.LOCK_UN)
			for _, held := range []bool{true, false} {
				if !held {
					if err := unix.Flock(int(directory.Fd()), unix.LOCK_UN); err != nil {
						t.Fatal(err)
					}
				}
				for _, tool := range agentintegration.Tools() {
					for _, operation := range []string{"install", "update", "remove"} {
						value := integrationLifecycleCLI(t, integrationLifecyclePlanArgs(root, tool, operation), 1)
						assertIntegrationLifecycleRoot(t, value, true)
						state, failure := "recovery_required", "pending_transaction_state"
						var recovery any = transaction
						if held {
							state, failure, recovery = "blocked", "transaction_busy", nil
						}
						if value["state"] != state || value["failureClass"] != failure || value["recoveryTransactionId"] != recovery || value["transaction"] != nil || value["tool"] != tool || value["operation"] != operation {
							t.Fatalf("live/abandoned plan projection changed: held=%v value=%#v", held, value)
						}
					}
				}
				if !reflect.DeepEqual(before, recoveryCLITree(t, root)) {
					t.Fatal("planning changed target or control state")
				}
			}
		})
	}
}

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
