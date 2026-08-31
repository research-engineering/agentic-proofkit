// Package diagnostic owns terminal-safe projection of errors for CLI tools.
package diagnostic

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// Text returns the fixed-label structural projection of an error.
func Text(err error) string {
	if err == nil {
		return ""
	}
	return admit.RedactDiagnosticValue(err.Error())
}

// WriteError writes one sanitized diagnostic line when err is non-nil.
func WriteError(writer io.Writer, err error) {
	if err == nil {
		return
	}
	_, _ = fmt.Fprintln(writer, Text(err))
}
