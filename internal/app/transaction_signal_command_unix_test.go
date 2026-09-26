//go:build darwin || linux

package app

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type transactionSignalFixture struct {
	root      string
	args      []string
	input     []byte
	wantState string
	mutates   bool
}

func newTransactionSignalFixture(t *testing.T, route string) transactionSignalFixture {
	t.Helper()
	fixture := transactionSignalFixture{root: t.TempDir()}
	switch route {
	case "adoption-plan", "adoption-apply":
		payload, transaction, desired := adoptionMaterializationPlanFixture(t, fixture.root)
		fixture.input = payload
		fixture.args = []string{"adopt", "materialize", "plan", "--input", "-", "--repo-root", fixture.root}
		if route == "adoption-apply" {
			fixture.args[2] = "apply"
			fixture.args = append(fixture.args, "--expect-transaction", transaction, "--expect-desired-state", desired)
			fixture.wantState, fixture.mutates = "passed", true
		}
	case "integration-plan", "integration-apply":
		fixture.args = integrationLifecyclePlanArgs(fixture.root, "claude", "install")
		if route == "integration-apply" {
			plan := integrationLifecycleCLI(t, fixture.args, 0)
			fixture.args = integrationLifecycleApplyArgs(fixture.root, "claude", "install", plan)
			fixture.wantState, fixture.mutates = "passed", true
		}
	case "adoption-recover", "integration-recover":
		root, transaction, action := recoveryCLIFixture(t, "ready")
		fixture.root = root
		fixture.args = []string{"integration", "recover"}
		if route == "adoption-recover" {
			fixture.args = []string{"adopt", "materialize", "recover"}
		}
		fixture.args = append(fixture.args, "--repo-root", root, "--transaction", transaction, "--action", action)
		fixture.wantState, fixture.mutates = "passed", true
	case "residue-inspect", "residue-quarantine":
		residueCLIFixture(t, fixture.root, []byte("{\"retained\":"))
		fixture.args = residueCLIArgs(fixture.root, "inspect-residue")
		fixture.wantState = "eligible"
		if route == "residue-quarantine" {
			observed := residueCLIOutput(t, fixture.args, "eligible", nil)
			fixture.args = residueCLIArgs(fixture.root, "quarantine-residue", observed["observationId"].(string))
			fixture.wantState, fixture.mutates = "quarantined", true
		}
	default:
		t.Fatalf("unknown signal fixture %q", route)
	}
	return fixture
}

func TestTransactionSignalCommandBoundary(t *testing.T) {
	for _, route := range []string{"adoption-plan", "adoption-apply", "adoption-recover", "integration-plan", "integration-apply", "integration-recover", "residue-inspect", "residue-quarantine"} {
		for _, format := range []string{"json", "text"} {
			for _, signalCase := range []string{"none", "INT", "TERM"} {
				t.Run(strings.Join([]string{route, format, signalCase}, "/"), func(t *testing.T) {
					fixture := newTransactionSignalFixture(t, route)
					before := residueCLITree(t, fixture.root)
					beforeValues := recoveryCLITree(t, fixture.root)
					args := append(fixture.args, "--format", format)
					var expectedDiagnostic bytes.Buffer
					if signalCase != "none" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						var output bytes.Buffer
						code := Run(ctx, args, bytes.NewReader(fixture.input), &output, &expectedDiagnostic)
						if code != 1 || output.Len() != 0 || expectedDiagnostic.Len() == 0 || strings.Contains(expectedDiagnostic.String(), fixture.root) {
							t.Fatal("caller cancellation did not preserve operational-error output")
						}
						assertResidueCLITree(t, before, residueCLITree(t, fixture.root))
					}
					process := startTransactionSignalProcess(t, transactionSignalCase{Mode: "app", Args: args, Input: fixture.input, Canceled: signalCase != "none"})
					process.expect(t, "ARMED")
					if signalCase != "none" {
						for _, signal := range transactionTestSignals {
							if signal.name == signalCase {
								process.signal(t, signal.signal)
							}
						}
						process.expect(t, "RESTORED")
					}
					process.send(t, "GO")
					if signalCase != "none" {
						process.expectExit(t, 1)
						if process.stdout.Len() != 0 || process.stderr.String() != expectedDiagnostic.String() {
							t.Fatalf("cancellation streams: %q %q", process.stdout.String(), process.stderr.String())
						}
						assertResidueCLITree(t, before, residueCLITree(t, fixture.root))
						return
					}
					process.expectExit(t, 0)
					if process.stdout.Len() == 0 || process.stderr.Len() != 0 {
						t.Fatalf("positive streams: %q %q", process.stdout.String(), process.stderr.String())
					}
					if format == "json" && fixture.wantState != "" {
						value := decodeCLIJSON(t, process.stdout.String()).(map[string]any)
						if value["state"] != fixture.wantState {
							t.Fatalf("positive state=%v want=%s", value["state"], fixture.wantState)
						}
					}
					if fixture.mutates {
						if reflect.DeepEqual(beforeValues, recoveryCLITree(t, fixture.root)) {
							t.Fatal("mutating positive control had no native effect")
						}
					} else {
						assertResidueCLITree(t, before, residueCLITree(t, fixture.root))
					}
				})
			}
		}
	}
}

func TestTransactionSignalDefaultStdinInterruption(t *testing.T) {
	for _, route := range []string{"self-check", "adoption-apply"} {
		for _, signalCase := range []string{"none", "INT", "TERM"} {
			t.Run(fmt.Sprintf("%s/%s", route, signalCase), func(t *testing.T) {
				fixture := transactionSignalFixture{root: t.TempDir(), args: []string{"self-check", "--input", "-"}, input: []byte(`{"ok":true}`)}
				if route == "adoption-apply" {
					fixture = newTransactionSignalFixture(t, route)
				}
				before := residueCLITree(t, fixture.root)
				beforeValues := recoveryCLITree(t, fixture.root)
				process := startTransactionSignalProcess(t, transactionSignalCase{Mode: "stdin", Args: fixture.args})
				process.expect(t, "INPUT_ENTERED")
				if signalCase != "none" {
					for _, signal := range transactionTestSignals {
						if signal.name == signalCase {
							process.signal(t, signal.signal)
							process.expectSignal(t, signal.signal)
						}
					}
					assertResidueCLITree(t, before, residueCLITree(t, fixture.root))
					return
				}
				if _, err := process.stdin.Write(fixture.input); err != nil {
					t.Fatal(err)
				}
				if err := process.stdin.Close(); err != nil {
					t.Fatal(err)
				}
				process.expectExit(t, 0)
				value := decodeCLIJSON(t, process.stdout.String()).(map[string]any)
				if value["state"] != "passed" || process.stderr.Len() != 0 {
					t.Fatalf("input positive result: %q %q", process.stdout.String(), process.stderr.String())
				}
				if fixture.mutates && reflect.DeepEqual(beforeValues, recoveryCLITree(t, fixture.root)) {
					t.Fatal("input positive did not apply its transaction")
				}
			})
		}
	}
}
