package app

import (
	"fmt"
	"io"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func writeJSON(value any, exitCode int, err error, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	output, err := stablejson.MarshalLayout(value, jsonLayoutFromWriter(stdout))
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if err := writeAll(stdout, output); err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return exitCode
}

func writeText(value string, exitCode int, err error, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if err := writeAll(stdout, []byte(value)); err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return exitCode
}

func writeDiagnostic(stderr io.Writer, err error) {
	if err == nil {
		return
	}
	writeDiagnosticText(stderr, diagnosticMessage(err))
}

func writeDiagnosticf(stderr io.Writer, format string, args ...any) {
	writeDiagnosticText(stderr, sanitizeDiagnosticText(fmt.Sprintf(format, args...)))
}

func writeDiagnosticText(stderr io.Writer, message string) {
	_, _ = fmt.Fprintln(stderr, sanitizeDiagnosticText(message))
}

func diagnosticMessage(err error) string {
	if err == nil {
		return ""
	}
	return sanitizeDiagnosticText(err.Error())
}

func sanitizeDiagnosticText(message string) string {
	return admit.RedactDiagnosticValue(message)
}

func writeAll(writer io.Writer, output []byte) error {
	written, err := writer.Write(output)
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if written != len(output) {
		return fmt.Errorf("write output: short write")
	}
	return nil
}

func readInput(path string, stdin io.Reader) (any, error) {
	if path == "-" {
		return admission.DecodeJSON(stdin, maxInputBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return admission.DecodeJSON(file, maxInputBytes)
}
