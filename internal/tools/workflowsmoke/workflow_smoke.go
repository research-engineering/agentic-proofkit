package workflowsmoke

import (
	"bytes"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const workflowInput = `{"checkpoint":{"state":"not_started"},"completedStageIds":[],"contextRefs":[],"governingAuthorityRefId":null,"requiredContextRefIds":[],"schemaVersion":1}`

// Result is the observable process contract for one installed CLI invocation.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Runner invokes one installed carrier with the supplied stdin and argv.
type Runner func(input []byte, args ...string) (Result, error)

// Verify exercises the public agent-workflow relation through one installed
// CLI carrier. It owns expectations; carrier adapters own process execution.
func Verify(run Runner) error {
	input := []byte(workflowInput)

	plan, err := invoke(run, "planner JSON", input, "change-workflow-plan", "--input", "-")
	if err != nil {
		return err
	}
	planValue, err := verifyJSONObject(plan, "planner JSON")
	if err != nil {
		return err
	}
	if err := requireString(planValue, "reportKind", "proofkit.change-workflow-plan"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}
	if err := requireString(planValue, "reportId", "proofkit.change-workflow-plan"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}
	if err := requireString(planValue, "outputKind", "next_action"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}
	if err := requireString(planValue, "activeStageId", "architecture"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}
	if err := requireString(planValue, "action", "author"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}
	if err := requireString(planValue, "checkpointState", "not_started"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}
	if err := requireString(planValue, "workflowProfileId", "proofkit.reviewed-change.v1"); err != nil {
		return fmt.Errorf("planner JSON: %w", err)
	}

	compact, err := invoke(run, "planner compact JSON", input, "--json-layout", "compact", "change-workflow-plan", "--input", "-")
	if err != nil {
		return err
	}
	compactValue, err := verifyJSONObject(compact, "planner compact JSON")
	if err != nil {
		return err
	}
	if err := verifyCanonicalCompactJSON(compact.Stdout, compactValue); err != nil {
		return fmt.Errorf("planner compact JSON: %w", err)
	}

	envelope, err := invoke(run, "planner agent envelope", input, "change-workflow-plan", "--input", "-", "--agent-envelope")
	if err != nil {
		return err
	}
	envelopeValue, err := verifyJSONObject(envelope, "planner agent envelope")
	if err != nil {
		return err
	}
	if err := requireString(envelopeValue, "envelopeId", "proofkit.change-workflow-plan.agent-envelope"); err != nil {
		return fmt.Errorf("planner agent envelope: %w", err)
	}
	sourceReport, ok := envelopeValue["sourceReport"].(map[string]any)
	if !ok {
		return fmt.Errorf("planner agent envelope: sourceReport must be an object")
	}
	for field, want := range map[string]string{"reportId": "proofkit.change-workflow-plan", "reportKind": "proofkit.change-workflow-plan", "state": "passed"} {
		if err := requireString(sourceReport, field, want); err != nil {
			return fmt.Errorf("planner agent envelope sourceReport: %w", err)
		}
	}

	text, err := invoke(run, "planner text", input, "change-workflow-plan", "--input", "-", "--format", "text", "--color", "never")
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(text.Stdout, []byte("Change workflow plan\n")) || bytes.Contains(text.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("planner text must be plain text with the canonical heading")
	}

	if err := verifyFailure(run, "required input", nil, "requires --input <path|->", "change-workflow-plan"); err != nil {
		return err
	}
	if err := verifyFailure(run, "pre-read input pointer", nil, "JSON pointer", "change-workflow-plan", "--input", "proofkit-smoke-missing-input.json", "--input-pointer", "invalid"); err != nil {
		return err
	}
	if err := verifyFailure(run, "JSON color denial", input, "--color is valid only with --format text", "change-workflow-plan", "--input", "-", "--color", "never"); err != nil {
		return err
	}
	if err := verifyFailure(run, "exclusive help", input, "help accepts no additional arguments", "change-workflow-plan", "--help", "--format", "text"); err != nil {
		return err
	}
	if err := verifyFailure(run, "surplus positional operand", input, "unsupported argument", "change-workflow-plan", "--input", "-", "surplus"); err != nil {
		return err
	}

	help, err := invoke(run, "exclusive help success", []byte("must remain unread"), "change-workflow-plan", "--help")
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(help.Stdout, []byte("Usage:\n")) || bytes.Contains(help.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("exclusive help success must emit plain command help")
	}

	guidance, err := invoke(run, "no-input guidance JSON", []byte("must remain unread"), "native-evidence-guidance")
	if err != nil {
		return err
	}
	guidanceValue, err := verifyJSONObject(guidance, "no-input guidance JSON")
	if err != nil {
		return err
	}
	if err := requireString(guidanceValue, "guidanceId", "proofkit.native-evidence-guidance.v1"); err != nil {
		return fmt.Errorf("no-input guidance JSON: %w", err)
	}
	slots, ok := guidanceValue["slots"].([]any)
	if !ok || len(slots) != 22 {
		return fmt.Errorf("no-input guidance JSON: slots must contain 22 records")
	}
	if err := requireStringObject(slots[0], "slotId", "semantic_owner"); err != nil {
		return fmt.Errorf("no-input guidance JSON: first slot: %w", err)
	}
	if err := requireStringObject(slots[0], "applicabilityClass", "always"); err != nil {
		return fmt.Errorf("no-input guidance JSON: first slot: %w", err)
	}
	if err := requireStringObject(slots[len(slots)-1], "slotId", "non_claims"); err != nil {
		return fmt.Errorf("no-input guidance JSON: last slot: %w", err)
	}

	guidanceText, err := invoke(run, "no-input guidance text", []byte("must remain unread"), "native-evidence-guidance", "--format", "text", "--color", "never")
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(guidanceText.Stdout, []byte("semantic_owner: applicability: always; decision:")) || bytes.Contains(guidanceText.Stdout, []byte("\x1b[")) {
		return fmt.Errorf("no-input guidance text must be plain text with the canonical first slot")
	}
	return nil
}

func invoke(run Runner, label string, input []byte, args ...string) (Result, error) {
	result, err := run(input, args...)
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

func verifyFailure(run Runner, label string, input []byte, diagnosticFragment string, args ...string) error {
	result, err := run(input, args...)
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

func verifyJSONObject(result Result, label string) (map[string]any, error) {
	value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), int64(len(result.Stdout)))
	if err != nil {
		return nil, fmt.Errorf("%s stdout must contain exactly one strict JSON value: %w", label, err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s stdout JSON must be an object", label)
	}
	return record, nil
}

func verifyCanonicalCompactJSON(output []byte, value any) error {
	canonical, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		return err
	}
	if !bytes.Equal(output, canonical) || bytes.Count(output, []byte{'\n'}) != 1 {
		return fmt.Errorf("stdout is not one newline-terminated canonical compact JSON value")
	}
	return nil
}

func requireString(record map[string]any, field string, want string) error {
	got, ok := record[field].(string)
	if !ok || got != want {
		return fmt.Errorf("%s=%v, want %q", field, record[field], want)
	}
	return nil
}

func requireStringObject(value any, field string, want string) error {
	record, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("value must be an object")
	}
	return requireString(record, field, want)
}
