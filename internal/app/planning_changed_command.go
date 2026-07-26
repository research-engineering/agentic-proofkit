package app

import (
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/changedpathset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func runChangedPathSetPlanning(input any, options planningArgs, stdout io.Writer, stderr io.Writer) int {
	result, err := changedpathset.Build(input)
	if err != nil {
		if options.agentEnvelope {
			return writeJSON(agentenvelope.InvalidInput(err.Error()), 1, nil, stdout, stderr)
		}
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.agentEnvelope {
		return writeJSON(changedpathset.AgentEnvelope(result), result.ExitCode, nil, stdout, stderr)
	}
	return writeJSON(result.JSONValue(), result.ExitCode, nil, stdout, stderr)
}
