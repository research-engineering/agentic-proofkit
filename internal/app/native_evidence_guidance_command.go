package app

import (
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
)

func runNativeEvidenceGuidance(options agentWorkflowArgs, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	if options.format == "json" {
		guidance, err := nativeevidenceguidance.Build()
		if err != nil {
			return writeJSON(nil, 0, err, stdout, stderr)
		}
		return writeJSON(guidance.JSONValue(), 0, nil, stdout, stderr)
	}
	view, err := nativeEvidenceGuidanceTerminalText()
	if err != nil {
		return writeText("", 1, err, stdout, stderr)
	}
	output, err := renderTerminalText(view, options.color, capabilities)
	return writeText(output, 0, err, stdout, stderr)
}

func nativeEvidenceGuidanceTerminalText() (terminalText, error) {
	lines, err := nativeevidenceguidance.TextProjection()
	if err != nil {
		return terminalText{}, err
	}
	tokens := make([]terminalTextToken, 0, len(lines)*2)
	for _, line := range lines {
		tokens = append(tokens,
			terminalTextToken{kind: terminalTokenLabel, text: line.Label},
			terminalTextToken{kind: terminalTokenPlain, text: ": " + line.Value + "\n"},
		)
	}
	return newTerminalText(tokens...), nil
}
