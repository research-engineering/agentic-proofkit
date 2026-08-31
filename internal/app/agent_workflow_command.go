package app

import (
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/changeworkflowplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runAgentWorkflowCommand(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	options, err := parseAgentWorkflowArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	switch command {
	case "native-evidence-guidance":
		return runNativeEvidenceGuidance(options, stdout, stderr, capabilities)
	case "change-workflow-plan":
		// Continue through the explicit-input transport below.
	default:
		writeDiagnosticf(stderr, "unsupported agent workflow command")
		return 1
	}
	input, err := readInput(options.inputPath, stdin)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.pointerPresent {
		input, err = jsonpointer.SelectParsed(input, options.inputPointer)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	if options.agentEnvelope {
		output, err := changeworkflowplan.BuildAgentEnvelope(input)
		return writeJSON(output, 0, err, stdout, stderr)
	}
	if options.format == "text" {
		lines, err := changeworkflowplan.BuildTextProjection(input)
		if err != nil {
			return writeText("", 1, err, stdout, stderr)
		}
		view := changeWorkflowTerminalText(lines)
		output, err := renderTerminalText(view, options.color, capabilities)
		return writeText(output, 0, err, stdout, stderr)
	}
	output, err := changeworkflowplan.Build(input)
	return writeJSON(output, 0, err, stdout, stderr)
}

func changeWorkflowTerminalText(lines []changeworkflowplan.TextLine) terminalText {
	tokens := make([]terminalTextToken, 0, len(lines)*2)
	for _, line := range lines {
		tokens = append(tokens, terminalTextToken{kind: terminalTokenLabel, text: line.Label})
		if line.Value == "" {
			tokens = append(tokens, terminalTextToken{kind: terminalTokenPlain, text: "\n"})
			continue
		}
		tokens = append(tokens, terminalTextToken{kind: terminalTokenPlain, text: ": " + line.Value + "\n"})
	}
	return newTerminalText(tokens...)
}
