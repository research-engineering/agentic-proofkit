package workflowsmoke

import (
	"bytes"
	"context"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func verifyCapabilityInputGuide(ctx context.Context, run Runner) error {
	help, err := invoke(ctx, run, "capability input guide", unreadInvocation("capability-map-admission", "--help"))
	if err != nil {
		return err
	}
	if bytes.Count(help.Stdout, []byte(capabilitymapadmission.InputGuide)) != 1 {
		return fmt.Errorf("installed capability help must expose the exact command-owned input guide")
	}
	sections := bytes.Split(help.Stdout, []byte("```json\n"))
	if len(sections) != 3 {
		return fmt.Errorf("installed capability help must contain two complete JSON examples")
	}
	for index, section := range sections[1:] {
		input, _, closed := bytes.Cut(section, []byte("\n```"))
		if !closed {
			return fmt.Errorf("installed capability help example must have a closing fence")
		}
		value, err := admission.DecodeJSON(bytes.NewReader(input), defaultMaximumStdoutBytes)
		if err != nil {
			return fmt.Errorf("decode installed capability help example: %w", err)
		}
		expected, exitCode, err := capabilitymapadmission.Build(value)
		if err != nil || exitCode != 0 {
			return fmt.Errorf("installed capability help example %d must pass native admission", index)
		}
		result, err := invoke(ctx, run, "capability help example", bytesInvocation(input, "capability-map-admission", "--input", "-"))
		if err != nil {
			return err
		}
		if err := verifyExactJSONObject(result, expected.JSONValue(), "capability help example"); err != nil {
			return err
		}
	}
	return nil
}
