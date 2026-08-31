package workflowsmoke

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/changeworkflowplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	workflowInput     = `{"checkpoint":{"state":"not_started"},"completedStageIds":[],"contextRefs":[],"governingAuthorityRefId":null,"requiredContextRefIds":[],"schemaVersion":1}`
	invocationTimeout = 30 * time.Second
)

// Result is the observable process contract for one installed CLI invocation.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// StdinClass declares whether an invocation owns stdin bytes or must not read
// stdin at all.
type StdinClass uint8

const (
	StdinBytes StdinClass = iota
	StdinMustRemainUnread
)

// Invocation is one immutable installed-carrier request.
type Invocation struct {
	Args       []string
	Input      []byte
	StdinClass StdinClass
}

// Runner invokes one installed carrier under the supplied lifecycle context.
type Runner func(context.Context, Invocation) (Result, error)

// Verify exercises the public agent-workflow relation through one installed
// CLI carrier. Command owners provide exact expectations; adapters own only
// process execution.
func Verify(ctx context.Context, run Runner) error {
	if ctx == nil || run == nil {
		return fmt.Errorf("workflow smoke requires a context and runner")
	}
	input := []byte(workflowInput)
	inputValue, err := admission.DecodeJSON(bytes.NewReader(input), int64(len(input)))
	if err != nil {
		return fmt.Errorf("decode workflow smoke fixture: %w", err)
	}
	expectedPlan, err := changeworkflowplan.Build(inputValue)
	if err != nil {
		return fmt.Errorf("build expected planner JSON: %w", err)
	}
	expectedEnvelope, err := changeworkflowplan.BuildAgentEnvelope(inputValue)
	if err != nil {
		return fmt.Errorf("build expected planner envelope: %w", err)
	}
	expectedText, err := changeworkflowplan.BuildText(inputValue)
	if err != nil {
		return fmt.Errorf("build expected planner text: %w", err)
	}
	expectedGuidance, err := nativeevidenceguidance.Build()
	if err != nil {
		return fmt.Errorf("build expected native evidence guidance: %w", err)
	}
	expectedGuidanceText, err := nativeevidenceguidance.RenderPlainText()
	if err != nil {
		return fmt.Errorf("build expected native evidence guidance text: %w", err)
	}

	plan, err := invoke(ctx, run, "planner JSON", bytesInvocation(input, "change-workflow-plan", "--input", "-"))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(plan, expectedPlan, "planner JSON"); err != nil {
		return err
	}

	compact, err := invoke(ctx, run, "planner compact JSON", bytesInvocation(input, "--json-layout", "compact", "change-workflow-plan", "--input", "-"))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(compact, expectedPlan, "planner compact JSON"); err != nil {
		return err
	}
	if err := verifyCanonicalCompactJSON(compact.Stdout, expectedPlan); err != nil {
		return fmt.Errorf("planner compact JSON: %w", err)
	}

	envelope, err := invoke(ctx, run, "planner agent envelope", bytesInvocation(input, "change-workflow-plan", "--input", "-", "--agent-envelope"))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(envelope, expectedEnvelope, "planner agent envelope"); err != nil {
		return err
	}

	text, err := invoke(ctx, run, "planner text", bytesInvocation(input, "change-workflow-plan", "--input", "-", "--format", "text", "--color", "never"))
	if err != nil {
		return err
	}
	if !bytes.Equal(text.Stdout, []byte(expectedText)) || bytes.Contains(text.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("planner text does not equal the command-owned plain-text projection")
	}

	if err := verifyFailure(ctx, run, "required input", bytesInvocation(nil, "change-workflow-plan"), "requires --input <path|->"); err != nil {
		return err
	}
	if err := verifyFailure(ctx, run, "pre-read input pointer", bytesInvocation(nil, "change-workflow-plan", "--input", "proofkit-smoke-missing-input.json", "--input-pointer", "invalid"), "JSON pointer"); err != nil {
		return err
	}
	if err := verifyFailure(ctx, run, "JSON color denial", bytesInvocation(input, "change-workflow-plan", "--input", "-", "--color", "never"), "--color is valid only with --format text"); err != nil {
		return err
	}
	if err := verifyFailure(ctx, run, "exclusive help", bytesInvocation(input, "change-workflow-plan", "--help", "--format", "text"), "help accepts no additional arguments"); err != nil {
		return err
	}
	if err := verifyFailure(ctx, run, "surplus positional operand", bytesInvocation(input, "change-workflow-plan", "--input", "-", "surplus"), "unsupported argument"); err != nil {
		return err
	}

	help, err := invoke(ctx, run, "exclusive help success", unreadInvocation("change-workflow-plan", "--help"))
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(help.Stdout, []byte("Usage:\n")) || bytes.Contains(help.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("exclusive help success must emit plain command help")
	}

	guidance, err := invoke(ctx, run, "no-input guidance JSON", unreadInvocation("native-evidence-guidance"))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(guidance, expectedGuidance.JSONValue(), "no-input guidance JSON"); err != nil {
		return err
	}

	guidanceText, err := invoke(ctx, run, "no-input guidance text", unreadInvocation("native-evidence-guidance", "--format", "text", "--color", "never"))
	if err != nil {
		return err
	}
	if !bytes.Equal(guidanceText.Stdout, []byte(expectedGuidanceText)) || bytes.Contains(guidanceText.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("no-input guidance text does not equal the command-owned plain-text projection")
	}
	return nil
}

func bytesInvocation(input []byte, args ...string) Invocation {
	return Invocation{Args: append([]string(nil), args...), Input: append([]byte(nil), input...), StdinClass: StdinBytes}
}

func unreadInvocation(args ...string) Invocation {
	return Invocation{Args: append([]string(nil), args...), StdinClass: StdinMustRemainUnread}
}

func invoke(ctx context.Context, run Runner, label string, invocation Invocation) (Result, error) {
	invocationContext, cancel := context.WithTimeout(ctx, invocationTimeout)
	defer cancel()
	result, err := run(invocationContext, invocation)
	if err != nil {
		return Result{}, fmt.Errorf("%s carrier invocation: %w", label, err)
	}
	if result.ExitCode != 0 {
		return Result{}, fmt.Errorf("%s exit code=%d, want 0", label, result.ExitCode)
	}
	if len(result.Stderr) != 0 {
		return Result{}, fmt.Errorf("%s stderr must be empty", label)
	}
	if len(result.Stdout) == 0 {
		return Result{}, fmt.Errorf("%s stdout must not be empty", label)
	}
	return result, nil
}

func verifyFailure(ctx context.Context, run Runner, label string, invocation Invocation, diagnosticFragment string) error {
	invocationContext, cancel := context.WithTimeout(ctx, invocationTimeout)
	defer cancel()
	result, err := run(invocationContext, invocation)
	if err != nil {
		return fmt.Errorf("%s carrier invocation: %w", label, err)
	}
	if result.ExitCode != 1 || len(result.Stdout) != 0 || len(result.Stderr) == 0 {
		return fmt.Errorf("%s must fail with exit 1, empty stdout, and nonempty stderr", label)
	}
	if bytes.Contains(result.Stderr, []byte("\x1b[")) || !bytes.Contains(result.Stderr, []byte(diagnosticFragment)) {
		return fmt.Errorf("%s diagnostic does not contain the required safe class", label)
	}
	return nil
}

func verifyExactJSONObject(result Result, expected map[string]any, label string) error {
	actual, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), maximumStdoutBytes)
	if err != nil {
		return fmt.Errorf("%s stdout must contain exactly one strict JSON value: %w", label, err)
	}
	if _, ok := actual.(map[string]any); !ok {
		return fmt.Errorf("%s stdout JSON must be an object", label)
	}
	actualCanonical, err := stablejson.MarshalLayout(actual, stablejson.LayoutCompact)
	if err != nil {
		return fmt.Errorf("%s actual JSON is not canonicalizable: %w", label, err)
	}
	expectedCanonical, err := stablejson.MarshalLayout(expected, stablejson.LayoutCompact)
	if err != nil {
		return fmt.Errorf("%s expected JSON is not canonicalizable: %w", label, err)
	}
	if !bytes.Equal(actualCanonical, expectedCanonical) {
		return fmt.Errorf("%s JSON does not equal the command-owned projection", label)
	}
	return nil
}

func verifyCanonicalCompactJSON(output []byte, expected map[string]any) error {
	canonical, err := stablejson.MarshalLayout(expected, stablejson.LayoutCompact)
	if err != nil {
		return err
	}
	if !bytes.Equal(output, canonical) || bytes.Count(output, []byte{'\n'}) != 1 {
		return fmt.Errorf("stdout is not one newline-terminated canonical compact JSON value")
	}
	return nil
}
