package diagnostic

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteErrorPreservesSafeTextAndRedactsRejectedValuesAsAWhole(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "safe", text: "package verification failed", want: "package verification failed\n"},
		{name: "secret", text: "prefix api_key=abc123456789 suffix", want: "<redacted-diagnostic-value>\n"},
		{name: "control", text: "prefix\u202eraw suffix", want: "<redacted-diagnostic-value>\n"},
		{name: "split secret", text: "prefix api_\u200bkey=abc123456789 suffix", want: "<redacted-diagnostic-value>\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			WriteError(&output, errors.New(test.text))
			if got := output.String(); got != test.want {
				t.Fatalf("WriteError()=%q, want %q", got, test.want)
			}
			if test.want == "<redacted-diagnostic-value>\n" && (strings.Contains(output.String(), "prefix") || strings.Contains(output.String(), "suffix") || strings.Contains(output.String(), "abc123456789")) {
				t.Fatalf("WriteError() disclosed rejected fragments: %q", output.String())
			}
		})
	}
}

func TestWriteErrorIgnoresNil(t *testing.T) {
	var output bytes.Buffer
	WriteError(&output, nil)
	if output.Len() != 0 || Text(nil) != "" {
		t.Fatalf("nil error produced output %q", output.String())
	}
}

func TestDiagnosticTextEnforcesWholeValueSafetyAndRuneBound(t *testing.T) {
	if got := Text(errors.New(strings.Repeat("a", 512))); got != strings.Repeat("a", 512) {
		t.Fatalf("512-rune diagnostic changed: %q", got)
	}
	if got := Text(errors.New(strings.Repeat("a", 513))); got != strings.Repeat("a", 512)+"...<truncated-diagnostic>" {
		t.Fatalf("513-rune diagnostic was not bounded: %q", got)
	}
	if got := Text(errors.New(string([]byte{'g', 'h', 'p', '_', 0xff}))); got != "<redacted-diagnostic-value>" {
		t.Fatalf("malformed UTF-8 diagnostic was not redacted: %q", got)
	}
}

func TestStderrCaptureSanitizesWholeValuesAndBoundsMemory(t *testing.T) {
	secret := strings.Join([]string{"api", "_key=", "abc123456789"}, "")
	capture := NewStderrCapture()
	_, _ = capture.Write([]byte(secret))
	err := capture.Failure("child")
	if err == nil || strings.Contains(err.Error(), "abc123456789") || !strings.Contains(err.Error(), "<redacted-diagnostic-value>") {
		t.Fatalf("secret child stderr was not redacted: %v", err)
	}

	overflow := NewStderrCapture()
	_, _ = overflow.Write([]byte(strings.Repeat("x", maxCapturedStderrBytes+1)))
	err = overflow.Failure("child")
	if err == nil || err.Error() != "child exceeded the stderr capture limit" {
		t.Fatalf("overflow diagnostic = %v", err)
	}
}
