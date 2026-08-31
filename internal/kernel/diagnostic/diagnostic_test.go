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
