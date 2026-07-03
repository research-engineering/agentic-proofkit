package app

import (
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runAgentRoute(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parsePlanningArgs("agent-route", args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	input, err := readInput(options.inputPath, stdin)
	if err != nil {
		if options.agentEnvelope {
			return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
		}
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.inputPointer != "" {
		input, err = jsonpointer.Select(input, options.inputPointer)
		if err != nil {
			if options.agentEnvelope {
				return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
			}
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	if options.agentEnvelope {
		output, exitCode, err := agentroute.BuildEnvelope(input)
		if err != nil {
			return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
		}
		return writeJSON(output, exitCode, nil, stdout, stderr)
	}
	output, exitCode, err := agentroute.Build(input)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return writeJSON(output, exitCode, nil, stdout, stderr)
}
