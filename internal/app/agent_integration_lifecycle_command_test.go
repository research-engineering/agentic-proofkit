package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func integrationLifecycleCLI(t *testing.T, args []string, wantCode int) map[string]any {
	t.Helper()
	code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
	if code != wantCode || diagnostic != "" || strings.Contains(output, "\x1b") {
		t.Fatalf("lifecycle exit=%d want=%d diagnostic=%q", code, wantCode, diagnostic)
	}
	return decodeCLIJSON(t, output).(map[string]any)
}

func integrationLifecyclePlanArgs(root, tool, operation string) []string {
	return []string{"integration", "plan", "--tool", tool, "--operation", operation, "--repo-root", root}
}

func integrationLifecycleApplyArgs(root, tool, operation string, plan map[string]any) []string {
	transaction := plan["transaction"].(map[string]any)
	return []string{"integration", "apply", "--tool", tool, "--operation", operation, "--repo-root", root, "--expect-transaction", transaction["transactionId"].(string), "--expect-desired-state", transaction["desiredStateId"].(string)}
}

func assertIntegrationLifecycleRoot(t *testing.T, value map[string]any, plan bool) {
	t.Helper()
	fields := []string{"expectedDesiredStateId", "expectedTransactionId", "failureClass", "kind", "nonClaims", "operation", "schemaVersion", "state", "tool", "transactionResult"}
	wantKind := "proofkit.integration-receipt.v1"
	if plan {
		fields = []string{"failureClass", "kind", "nonClaims", "operation", "recoveryTransactionId", "schemaVersion", "state", "tool", "transaction"}
		wantKind = "proofkit.integration-plan.v1"
	}
	assertExactObjectKeys(t, value, fields, "integration lifecycle output")
	if value["kind"] != wantKind || len(value["nonClaims"].([]any)) != 3 {
		t.Fatal("lifecycle output identity or non-claims changed")
	}
	if plan && value["transaction"] != nil {
		if _, err := repositorytransaction.AdmitPlanOutput(value["transaction"]); err != nil {
			t.Fatal(err)
		}
	} else if !plan && value["transactionResult"] != nil {
		if _, err := repositorytransaction.AdmitResultOutput(value["transactionResult"]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationPlanCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.100499585455180558184680186149455671295538897549556316778137583216002856749965")
	for _, tool := range agentintegration.Tools() {
		root := t.TempDir()
		for _, operation := range []string{"install", "update", "remove"} {
			code := 0
			if operation == "update" {
				code = 1
			}
			value := integrationLifecycleCLI(t, integrationLifecyclePlanArgs(root, tool, operation), code)
			assertIntegrationLifecycleRoot(t, value, true)
			if value["tool"] != tool || value["operation"] != operation {
				t.Fatal("plan routing changed selected tool or operation")
			}
			if operation == "update" {
				if value["state"] != "blocked" || value["failureClass"] != "not_installed" || value["transaction"] != nil {
					t.Fatal("update of absent installation was accepted")
				}
				continue
			}
			transaction := value["transaction"].(map[string]any)
			for _, raw := range transaction["operations"].([]any) {
				op := raw.(map[string]any)
				want := "create"
				if operation == "remove" {
					want = "unchanged"
				}
				if op["action"] != want {
					t.Fatal("plan action changed")
				}
			}
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("planning wrote repository entries")
		}
	}
}

func TestIntegrationApplyCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.074646976815602003213124531518453340149790461050955348292553777176771465626278")
	for _, tool := range agentintegration.Tools() {
		t.Run(tool, func(t *testing.T) {
			root := t.TempDir()
			document := integrationDocument(t, tool)
			path := filepath.Join(root, document.JSONValue()["targetPath"].(string))
			for _, operation := range []string{"install", "update", "remove"} {
				if operation == "update" {
					capabilities, err := integrationCapabilities(commandDescriptorByName, generatedCommandContractMetadataByName)
					if err != nil {
						t.Fatal(err)
					}
					capabilities[0].ContractDigest = "sha256:" + strings.Repeat("1", 64)
					prior, err := agentintegration.Source(tool, capabilities)
					if err != nil || prior.Content() == document.Content() {
						t.Fatal("fixture needs a distinct admitted prior source")
					}
					seed, err := agentintegration.PlanLifecycle(t.Context(), root, prior, agentintegration.OperationUpdate)
					if err != nil {
						t.Fatal(err)
					}
					transaction, err := repositorytransaction.AdmitPlanOutput(seed.JSONValue()["transaction"])
					if err != nil {
						t.Fatal(err)
					}
					if receipt, err := agentintegration.ApplyLifecycle(t.Context(), root, prior, agentintegration.OperationUpdate, transaction.TransactionID, transaction.DesiredStateID); err != nil || receipt.ExitCode() != 0 {
						t.Fatalf("seed prior: %v", err)
					}
				}
				plan := integrationLifecycleCLI(t, integrationLifecyclePlanArgs(root, tool, operation), 0)
				args := integrationLifecycleApplyArgs(root, tool, operation, plan)
				receipt := integrationLifecycleCLI(t, args, 0)
				assertIntegrationLifecycleRoot(t, receipt, false)
				if receipt["state"] != "passed" || receipt["operation"] != operation || receipt["tool"] != tool {
					t.Fatal("apply emitted a false lifecycle outcome")
				}
				content, err := os.ReadFile(path)
				if operation == "remove" {
					if !os.IsNotExist(err) {
						t.Fatal("remove retained instructions")
					}
				} else if err != nil || string(content) != document.Content() {
					t.Fatal("apply did not install exact source bytes")
				}
				replay := integrationLifecycleCLI(t, args, 0)
				if replay["transactionResult"].(map[string]any)["state"] != "already_satisfied" {
					t.Fatal("repeat apply lost idempotence")
				}
			}
			plan := integrationLifecycleCLI(t, integrationLifecyclePlanArgs(root, tool, "install"), 0)
			if err := os.WriteFile(path, []byte("owner edit\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			blocked := integrationLifecycleCLI(t, integrationLifecycleApplyArgs(root, tool, "install", plan), 1)
			assertIntegrationLifecycleRoot(t, blocked, false)
			if blocked["state"] != "blocked" || blocked["failureClass"] != "unrecognized_bootstrap" {
				t.Fatal("local edit was overwritten")
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != "owner edit\n" {
				t.Fatal("conflict changed owner bytes")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"json", "text"} {
				args := append(integrationLifecycleApplyArgs(root, tool, "install", plan), "--format", format)
				code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
				if code != 1 || output != "" || !strings.Contains(diagnostic, "regular non-symlink") || strings.Contains(diagnostic, root) {
					t.Fatalf("operational stream: exit=%d output=%q diagnostic=%q", code, output, diagnostic)
				}
			}
		})
	}
}

func TestIntegrationRecoverCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.048616201957844566215569600371534815430881597384694966035981327906285948266263")
	t.Run("pending observation streams", testIntegrationRecoveryObservationStreams)
	root := t.TempDir()
	plan := integrationLifecycleCLI(t, integrationLifecyclePlanArgs(root, "codex", "install"), 0)
	integrationLifecycleCLI(t, integrationLifecycleApplyArgs(root, "codex", "install", plan), 0)
	tx := plan["transaction"].(map[string]any)["transactionId"].(string)
	args := []string{"integration", "recover", "--repo-root", root, "--transaction", tx, "--action", "resume"}
	receipt := integrationLifecycleCLI(t, args, 0)
	assertIntegrationLifecycleRoot(t, receipt, false)
	if receipt["state"] != "passed" || receipt["tool"] != nil || receipt["expectedDesiredStateId"] != nil || receipt["operation"] != "recover" {
		t.Fatal("generic recovery assumed current source or tool")
	}
	args[len(args)-1] = "rollback"
	blocked := integrationLifecycleCLI(t, args, 1)
	if blocked["state"] == "passed" {
		t.Fatal("committed transaction was rolled back by historical recovery")
	}
}

func TestIntegrationLifecycleInvocationAndPresentation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	id := "sha256:" + strings.Repeat("0", 64)
	for _, args := range [][]string{
		{"integration", "plan", "--repo-root", missing, "--tool", "codex"},
		{"integration", "plan", "--repo-root", missing, "--tool", "invalid", "--operation", "install"},
		{"integration", "plan", "--repo-root", missing, "--tool", "codex", "--operation", "install", "--tool", "claude"},
		{"integration", "plan", "--repo-root", missing, "--tool", "codex", "--operation", "install", "--input", "-"},
		{"integration", "plan", "--repo-root", missing, "--tool", "codex", "--operation", "install", "--color", "auto"},
		{"integration", "apply", "--repo-root", missing, "--tool", "codex", "--operation", "install", "--expect-transaction", "invalid", "--expect-desired-state", id},
		{"integration", "recover", "--repo-root", missing, "--transaction", id, "--action", "force"},
		{"integration", "recover", "--repo-root", missing, "--transaction", id, "--action", "resume", "--tool", "codex"},
	} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" || strings.Contains(diagnostic, "root") && !strings.Contains(diagnostic, "--repo-root") {
			t.Fatalf("invocation admission did not dominate I/O: %q", diagnostic)
		}
	}
	root := t.TempDir()
	args := append(integrationLifecyclePlanArgs(root, "codex", "install"), "--format", "text")
	code, plain, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
	if code != 0 || diagnostic != "" || strings.Contains(plain, "\x1b") || !strings.Contains(plain, "Integration plan: ready") {
		t.Fatal("text default is not plain or ready")
	}
	args = append(args, "--color", "auto")
	for _, capability := range []PresentationCapabilities{{StdoutIsTTY: true}, {StdoutIsTTY: true, NoColorPresent: true}, {}} {
		code, text, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, capability)
		color := capability.StdoutIsTTY && !capability.NoColorPresent
		if code != 0 || diagnostic != "" || strings.Contains(text, "\x1b") != color || !color && text != plain {
			t.Fatal("terminal capability changed text semantics")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := agentintegration.PlanLifecycle(ctx, root, integrationDocument(t, "codex"), "install"); err == nil {
		t.Fatal("cancelled plan succeeded")
	}
}
