package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func verifyProjectNavigation(ctx context.Context, run Runner) (returnErr error) {
	repositoryRoot, err := os.MkdirTemp("", "proofkit-workflow-smoke-")
	if err != nil {
		return fmt.Errorf("create workflow smoke repository: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, os.RemoveAll(repositoryRoot))
	}()

	expectedStatus, err := projectstatus.Inspect(ctx, repositoryRoot)
	if err != nil {
		return fmt.Errorf("build expected project status: %w", err)
	}
	expectedNext, err := projectstatus.NextFromStatus(expectedStatus)
	if err != nil {
		return fmt.Errorf("build expected project next action: %w", err)
	}
	expectedStatusText, err := projectstatus.StatusText(expectedStatus)
	if err != nil {
		return fmt.Errorf("build expected project status text: %w", err)
	}
	expectedStatusPlain, err := projectstatus.RenderText(expectedStatusText)
	if err != nil {
		return fmt.Errorf("render expected project status text: %w", err)
	}
	expectedNextText, err := projectstatus.NextText(expectedNext)
	if err != nil {
		return fmt.Errorf("build expected project next text: %w", err)
	}
	expectedNextPlain, err := projectstatus.RenderText(expectedNextText)
	if err != nil {
		return fmt.Errorf("render expected project next text: %w", err)
	}

	status, err := invoke(ctx, run, "project status JSON", unreadInvocation("status", "--repo-root", repositoryRoot))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(status, expectedStatus.JSONValue(), "project status JSON"); err != nil {
		return err
	}
	compactStatus, err := invoke(ctx, run, "project status compact JSON", unreadInvocation("--json-layout", "compact", "status", "--repo-root", repositoryRoot))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(compactStatus, expectedStatus.JSONValue(), "project status compact JSON"); err != nil {
		return err
	}
	if err := verifyCanonicalCompactJSON(compactStatus.Stdout, expectedStatus.JSONValue()); err != nil {
		return fmt.Errorf("project status compact JSON: %w", err)
	}
	statusText, err := invoke(ctx, run, "project status text", unreadInvocation("status", "--repo-root", repositoryRoot, "--format", "text", "--color", "never"))
	if err != nil {
		return err
	}
	if !bytes.Equal(statusText.Stdout, []byte(expectedStatusPlain)) || bytes.Contains(statusText.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("project status text does not equal the command-owned plain-text projection")
	}

	next, err := invoke(ctx, run, "project next JSON", unreadInvocation("next", "--repo-root", repositoryRoot))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(next, expectedNext.JSONValue(), "project next JSON"); err != nil {
		return err
	}
	nextText, err := invoke(ctx, run, "project next text", unreadInvocation("next", "--repo-root", repositoryRoot, "--format", "text", "--color", "never"))
	if err != nil {
		return err
	}
	if !bytes.Equal(nextText.Stdout, []byte(expectedNextPlain)) || bytes.Contains(nextText.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("project next text does not equal the command-owned plain-text projection")
	}
	if err := verifyFailure(ctx, run, "project status required root", unreadInvocation("status"), "requires --repo-root"); err != nil {
		return err
	}
	if err := verifyFailure(ctx, run, "project next JSON color denial", unreadInvocation("next", "--repo-root", repositoryRoot, "--color", "never"), "--color requires --format text"); err != nil {
		return err
	}
	return verifyMaterializedProjectNavigation(ctx, run, repositoryRoot)
}

func verifyMaterializedProjectNavigation(ctx context.Context, run Runner, repositoryRoot string) error {
	rawInput, input, err := materializationSmokeInput(ctx, repositoryRoot)
	if err != nil {
		return err
	}
	expectedPlan, err := adoptionmaterialization.BuildPlan(ctx, rawInput, repositoryRoot)
	if err != nil {
		return fmt.Errorf("build expected installed materialization plan: %w", err)
	}
	planResult, err := invoke(ctx, run, "installed materialization plan", bytesInvocation(input, "adopt", "materialize", "plan", "--input", "-", "--repo-root", repositoryRoot))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(planResult, expectedPlan.JSONValue(), "installed materialization plan"); err != nil {
		return err
	}
	applyResult, err := invoke(ctx, run, "installed materialization apply", bytesInvocation(
		input,
		"adopt", "materialize", "apply", "--input", "-", "--repo-root", repositoryRoot,
		"--expect-transaction", expectedPlan.Transaction.TransactionID,
		"--expect-desired-state", expectedPlan.Transaction.DesiredStateID,
	))
	if err != nil {
		return err
	}
	receiptValue, err := admission.DecodeJSON(bytes.NewReader(applyResult.Stdout), int64(len(applyResult.Stdout)))
	if err != nil {
		return fmt.Errorf("decode installed materialization receipt: %w", err)
	}
	receipt, err := adoptionmaterialization.AdmitReceiptOutput(receiptValue)
	if err != nil {
		return fmt.Errorf("admit installed materialization receipt: %w", err)
	}
	if receipt.State != adoptionmaterialization.ReceiptStatePassed || receipt.Operation != adoptionmaterialization.OperationApply || receipt.TransactionResult == nil || receipt.TransactionResult.State != repositorytransaction.StateApplied || receipt.ExpectedTransactionID != expectedPlan.Transaction.TransactionID || receipt.ExpectedDesiredStateID != expectedPlan.Transaction.DesiredStateID {
		return fmt.Errorf("installed materialization receipt does not prove the expected applied transaction")
	}
	if err := verifyInstalledProjectState(ctx, run, repositoryRoot, projectstatus.StateVerificationRequired, projectstatus.ActionRunRepositoryVerification, "materialized"); err != nil {
		return err
	}
	if len(expectedPlan.Manifest.Routes) == 0 {
		return fmt.Errorf("installed materialization plan has no routed child")
	}
	driftPath := filepath.Join(repositoryRoot, filepath.FromSlash(expectedPlan.Manifest.Routes[0].Path))
	file, err := os.OpenFile(driftPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open installed materialization child for drift: %w", err)
	}
	if _, writeErr := file.Write([]byte{'\n'}); writeErr != nil {
		_ = file.Close()
		return fmt.Errorf("drift installed materialization child: %w", writeErr)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close drifted installed materialization child: %w", err)
	}
	return verifyInstalledProjectState(ctx, run, repositoryRoot, projectstatus.StateStale, projectstatus.ActionRematerializeProject, "drifted materialized")
}

func verifyInstalledProjectState(ctx context.Context, run Runner, repositoryRoot string, wantState projectstatus.ProjectState, wantAction, label string) error {
	expectedStatus, err := projectstatus.Inspect(ctx, repositoryRoot)
	if err != nil {
		return fmt.Errorf("build expected %s project status: %w", label, err)
	}
	if expectedStatus.ProjectState != wantState || expectedStatus.NextAction.ActionClass != wantAction {
		return fmt.Errorf("expected %s project state/action is inconsistent", label)
	}
	statusResult, err := invoke(ctx, run, label+" project status", unreadInvocation("status", "--repo-root", repositoryRoot))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(statusResult, expectedStatus.JSONValue(), label+" project status"); err != nil {
		return err
	}
	expectedNext, err := projectstatus.NextFromStatus(expectedStatus)
	if err != nil {
		return fmt.Errorf("build expected %s project next action: %w", label, err)
	}
	nextResult, err := invoke(ctx, run, label+" project next action", unreadInvocation("next", "--repo-root", repositoryRoot))
	if err != nil {
		return err
	}
	return verifyExactJSONObject(nextResult, expectedNext.JSONValue(), label+" project next action")
}
