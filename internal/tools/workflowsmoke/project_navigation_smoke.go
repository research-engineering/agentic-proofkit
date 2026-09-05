package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
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
	return verifyFailure(ctx, run, "project next JSON color denial", unreadInvocation("next", "--repo-root", repositoryRoot, "--color", "never"), "--color requires --format text")
}
