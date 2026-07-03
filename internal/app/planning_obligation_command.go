package app

import (
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/obligationdecision"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func runObligationDecisionPlanning(input any, options planningArgs, stdout io.Writer, stderr io.Writer) int {
	result, err := obligationdecision.Build(input)
	if err != nil {
		if options.agentEnvelope {
			return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
		}
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.agentEnvelope {
		return writeJSON(obligationdecision.AgentEnvelope(result), result.ExitCode, nil, stdout, stderr)
	}
	return writeJSON(result.Report.JSONValue(), result.ExitCode, nil, stdout, stderr)
}
