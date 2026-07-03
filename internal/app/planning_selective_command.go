package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateevidence"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func runSelectivePlanning(command string, input any, options planningArgs, stdout io.Writer, stderr io.Writer) int {
	if command == "selective-gate-plan" {
		plan, exitCode, err := selectivegateplan.Build(input)
		if err != nil {
			if options.agentEnvelope {
				return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
			}
			writeDiagnostic(stderr, err)
			return 1
		}
		if options.agentEnvelope {
			return writeJSON(selectivegateplan.AgentEnvelope(plan), exitCode, nil, stdout, stderr)
		}
		return writeJSON(plan, exitCode, nil, stdout, stderr)
	}
	if command == "selective-gate-evidence" {
		result, err := selectivegateevidence.Build(input)
		if err != nil {
			if options.agentEnvelope {
				return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
			}
			writeDiagnostic(stderr, err)
			return 1
		}
		if options.agentEnvelope {
			return writeJSON(selectivegateevidence.AgentEnvelope(result), result.ExitCode, nil, stdout, stderr)
		}
		return writeJSON(result.Report.JSONValue(), result.ExitCode, nil, stdout, stderr)
	}
	if options.agentEnvelope {
		_, _ = fmt.Fprintf(stderr, "--agent-envelope is valid only for %s\n", agentEnvelopeCommandList())
		return 1
	}
	projected, err := selectivegateevidence.ProjectObligationDecision(input)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return writeJSON(projected, 0, nil, stdout, stderr)
}
