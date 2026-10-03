package diagnostic

import (
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// ParseFlags preserves parser results while sanitizing its complete diagnostic.
// The set must use ContinueOnError; callers own help and failure exit codes.
// Flag metadata and Usage must be trusted configuration; LF/TAB are layout.
func ParseFlags(set *flag.FlagSet, args []string, output io.Writer) error {
	if set.ErrorHandling() != flag.ContinueOnError {
		err := errors.New("diagnostic flag parsing requires ContinueOnError")
		WriteError(output, err)
		return err
	}
	previous := set.Output()
	capture := NewStderrCapture()
	set.SetOutput(capture)
	defer set.SetOutput(previous)
	err := set.Parse(args)
	capture.mu.Lock()
	raw, overflow := string(capture.content), capture.overflow
	capture.mu.Unlock()
	if overflow {
		_, _ = io.WriteString(output, "flag diagnostics exceeded the capture limit\n")
	} else if raw != "" {
		text := raw
		if admit.ContainsSecretLikeValue(raw) {
			text = admit.RedactDiagnosticValue(raw)
		} else {
			// Usage owns LF/TAB layout, not a weaker scalar or secret policy.
			plain := strings.ReplaceAll(strings.ReplaceAll(raw, "\n", " "), "\t", " ")
			if projected := admit.RedactDiagnosticValue(plain); projected != plain {
				text = projected
			}
		}
		if text != raw {
			text += "\n"
		}
		_, _ = io.WriteString(output, text)
	}
	return err
}
