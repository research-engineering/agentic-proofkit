package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func verifyIntegrationLifecycle(ctx context.Context, run Runner, tool string, source map[string]any) (returnErr error) {
	root, err := os.MkdirTemp("", "proofkit-managed-smoke-")
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(root)) }()
	content, contentOK := source["content"].(string)
	relative, pathOK := source["targetPath"].(string)
	if !contentOK || !pathOK || !filepath.IsLocal(relative) {
		return fmt.Errorf("managed integration source is incomplete")
	}
	neighbor := filepath.Join(root, "AGENTS.md")
	if err := os.WriteFile(neighbor, []byte("protected instructions\n"), 0o644); err != nil {
		return err
	}
	for _, operation := range []string{"install", "update", "remove"} {
		if operation == "update" {
			if err := seedPriorIntegration(ctx, root, tool, content); err != nil {
				return err
			}
			if _, err := integrationLifecycleRecord(ctx, run, []string{"integration", "check", "--tool", tool, "--repo-root", root}, 2, "proofkit.integration-check.v1", "stale"); err != nil {
				return err
			}
		}
		planArgs := []string{"integration", "plan", "--tool", tool, "--operation", operation, "--repo-root", root}
		before, err := integrationTree(root)
		if err != nil {
			return err
		}
		plan, err := integrationLifecycleRecord(ctx, run, planArgs, 0, "proofkit.integration-plan.v1", "ready")
		if err != nil {
			return err
		}
		after, err := integrationTree(root)
		if err != nil || !reflect.DeepEqual(before, after) {
			return fmt.Errorf("installed lifecycle plan mutated the repository")
		}
		transaction, err := repositorytransaction.AdmitPlanOutput(plan["transaction"])
		if err != nil {
			return err
		}
		apply := []string{"integration", "apply", "--tool", tool, "--operation", operation, "--repo-root", root, "--expect-transaction", transaction.TransactionID, "--expect-desired-state", transaction.DesiredStateID}
		for attempt := 0; attempt < 2; attempt++ {
			receipt, err := integrationLifecycleRecord(ctx, run, apply, 0, "proofkit.integration-receipt.v1", "passed")
			if err != nil {
				return err
			}
			result, err := repositorytransaction.AdmitResultOutput(receipt["transactionResult"])
			if err != nil || result.TransactionID != transaction.TransactionID || (attempt == 1 && result.State != repositorytransaction.StateAlreadySatisfied) {
				return fmt.Errorf("installed lifecycle receipt or replay differs")
			}
		}
		for _, path := range []string{relative, "proofkit/integrations/" + tool + ".v1.json"} {
			actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if operation == "remove" {
				if !os.IsNotExist(err) {
					return fmt.Errorf("installed lifecycle remove retained a selected file")
				}
			} else if err != nil || path == relative && string(actual) != content {
				return fmt.Errorf("installed lifecycle did not preserve source bytes")
			}
		}
		if operation != "update" {
			recover := []string{"integration", "recover", "--repo-root", root, "--transaction", transaction.TransactionID, "--action", "resume"}
			receipt, err := integrationLifecycleRecord(ctx, run, recover, 0, "proofkit.integration-receipt.v1", "passed")
			if err != nil {
				return err
			}
			if receipt["tool"] != nil || receipt["expectedDesiredStateId"] != nil || receipt["operation"] != "recover" {
				return fmt.Errorf("installed recovery invented current tool authority")
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, relative), []byte("local edit\n"), 0o644); err != nil {
		return err
	}
	before, err := integrationTree(root)
	if err != nil {
		return err
	}
	blocked, err := integrationLifecycleRecord(ctx, run, []string{"integration", "plan", "--tool", tool, "--operation", "install", "--repo-root", root}, 1, "proofkit.integration-plan.v1", "blocked")
	if err != nil {
		return err
	}
	if blocked["failureClass"] != "unrecognized_bootstrap" || blocked["transaction"] != nil {
		return fmt.Errorf("installed lifecycle did not preserve local edit conflict")
	}
	after, err := integrationTree(root)
	if err != nil || !reflect.DeepEqual(before, after) {
		return fmt.Errorf("installed lifecycle conflict changed files")
	}
	protected, err := os.ReadFile(neighbor)
	if err != nil || string(protected) != "protected instructions\n" {
		return fmt.Errorf("installed lifecycle changed adjacent instructions")
	}
	return nil
}

// This Source-produced prior is a synthetic fixture, not a released version.
// Seeding uses the native owner; the installed carrier must perform the update.
func seedPriorIntegration(ctx context.Context, root, tool, currentContent string) error {
	capabilities := make([]agentintegration.Capability, 0)
	for _, command := range agentintegration.ConsumedCommands() {
		capabilities = append(capabilities, agentintegration.Capability{Command: command, Route: []string{command}, ContractDigest: "sha256:" + strings.Repeat("1", 64)})
	}
	prior, err := agentintegration.Source(tool, capabilities)
	if err != nil || prior.Content() == currentContent {
		return fmt.Errorf("prior integration fixture must have distinct admitted source bytes")
	}
	plan, err := agentintegration.PlanLifecycle(ctx, root, prior, agentintegration.OperationUpdate)
	if err != nil {
		return err
	}
	transaction, err := repositorytransaction.AdmitPlanOutput(plan.JSONValue()["transaction"])
	if err != nil {
		return err
	}
	receipt, err := agentintegration.ApplyLifecycle(ctx, root, prior, agentintegration.OperationUpdate, transaction.TransactionID, transaction.DesiredStateID)
	if err != nil || receipt.ExitCode() != 0 {
		return fmt.Errorf("seed prior integration fixture failed")
	}
	return nil
}

func integrationLifecycleRecord(ctx context.Context, run Runner, args []string, wantExit int, kind, state string) (map[string]any, error) {
	invocationContext, cancel := context.WithTimeout(ctx, invocationTimeout)
	defer cancel()
	result, err := run(invocationContext, unreadInvocation(args...))
	if err != nil {
		return nil, err
	}
	if result.ExitCode != wantExit || len(result.Stderr) != 0 {
		return nil, fmt.Errorf("installed integration lifecycle process outcome differs")
	}
	value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), defaultMaximumStdoutBytes)
	if err != nil {
		return nil, err
	}
	record, ok := value.(map[string]any)
	if !ok || record["kind"] != kind || record["state"] != state {
		return nil, fmt.Errorf("installed integration lifecycle report outcome differs")
	}
	return record, nil
}
