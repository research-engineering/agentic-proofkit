package diagnostic

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestParseFlagsPreservesStandardParserObservations(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--help"}, {"-h"}, {"--check"}, {"--check=false"}, {"--check=TRUE"},
		{"--check=1"}, {"--check=bad"}, {"--missing"}, {"--label"},
		{"--label=value"}, {"positional"}, {"--", "--check"},
		{"--check=unsafe\u202etext"}, {"--check=" + string([]byte{0xff})},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var reference, actual, originalWriter bytes.Buffer
			standard := flag.NewFlagSet("tool", flag.ContinueOnError)
			standard.SetOutput(&reference)
			wantCheck := standard.Bool("check", false, "check output")
			wantLabel := standard.String("label", "", "output label")
			wantErr := standard.Parse(args)
			protected := flag.NewFlagSet("tool", flag.ContinueOnError)
			protected.SetOutput(&originalWriter)
			gotCheck := protected.Bool("check", false, "check output")
			gotLabel := protected.String("label", "", "output label")
			gotErr := ParseFlags(protected, args, &actual)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || errors.Is(gotErr, flag.ErrHelp) != errors.Is(wantErr, flag.ErrHelp) {
				t.Fatal("parser error identity changed")
			}
			if !bytes.Equal(actual.Bytes(), reference.Bytes()) || *gotCheck != *wantCheck || *gotLabel != *wantLabel || !slices.Equal(protected.Args(), standard.Args()) {
				t.Fatal("safe parser observations changed")
			}
			if protected.Output() != &originalWriter || originalWriter.Len() != 0 {
				t.Fatal("original writer was used during parsing or not restored")
			}
		})
	}
}

func TestParseFlagsRedactsWholeDiagnostics(t *testing.T) {
	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		t.Run(fixture.Name, func(t *testing.T) {
			set := flag.NewFlagSet("tool", flag.ContinueOnError)
			set.Bool("check", false, "check output")
			var output bytes.Buffer
			if err := ParseFlags(set, []string{"--check=" + fixture.Input}, &output); err == nil {
				t.Fatal("invalid boolean accepted")
			}
			if output.String() != "<redacted-diagnostic-value>\n" {
				t.Fatal("sensitive diagnostic escaped whole-value redaction")
			}
		})
	}
	for _, text := range []string{"unsafe\u202etext", string([]byte{0xff})} {
		set := flag.NewFlagSet("tool", flag.ContinueOnError)
		set.Usage = func() { _, _ = io.WriteString(set.Output(), text) }
		var output bytes.Buffer
		_ = ParseFlags(set, []string{"--help"}, &output)
		if output.String() != "<redacted-diagnostic-value>\n" {
			t.Fatal("unsafe diagnostic escaped whole-value redaction")
		}
	}
}

func TestParseFlagsCapturesSplitUsageAndBoundsOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		pieces []string
		want   string
	}{
		{"safe-layout", []string{"Usage:\n\t-check\n"}, "Usage:\n\t-check\n"},
		{"split", []string{"api_", "key=synthetic-fixture"}, "<redacted-diagnostic-value>\n"},
		{"layout-split-secret", []string{"api_\n", "key=synthetic-fixture"}, "<redacted-diagnostic-value>\n"},
		{"capture-bound", []string{strings.Repeat("x", maxCapturedStderrBytes)}, strings.Repeat("x", 512) + "...<truncated-diagnostic>\n"},
		{"overflow", []string{strings.Repeat("x", maxCapturedStderrBytes+1), "api_key=synthetic-fixture"}, "flag diagnostics exceeded the capture limit\n"},
		{"text-at-bound", []string{strings.Repeat("x", 512)}, strings.Repeat("x", 512)},
		{"text-bound", []string{strings.Repeat("x", 513)}, strings.Repeat("x", 512) + "...<truncated-diagnostic>\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			set := flag.NewFlagSet("tool", flag.ContinueOnError)
			set.Usage = func() {
				for _, piece := range test.pieces {
					_, _ = io.WriteString(set.Output(), piece)
				}
			}
			var output bytes.Buffer
			if err := ParseFlags(set, []string{"--help"}, &output); !errors.Is(err, flag.ErrHelp) {
				t.Fatal("help identity changed")
			}
			if output.String() != test.want {
				t.Fatal("split or bounded diagnostic mismatch")
			}
		})
	}
}

func TestParseFlagsRejectsNonReturningHandlersBeforeParsing(t *testing.T) {
	for _, mode := range []flag.ErrorHandling{flag.ExitOnError, flag.PanicOnError} {
		set := flag.NewFlagSet("tool", mode)
		set.SetOutput(io.Discard)
		check := set.Bool("check", false, "check output")
		var output bytes.Buffer
		err := ParseFlags(set, []string{"--check"}, &output)
		if err == nil || *check || set.Parsed() || set.Output() != io.Discard {
			t.Fatal("unsafe error handler was parsed or changed")
		}
		if output.String() != "diagnostic flag parsing requires ContinueOnError\n" {
			t.Fatal("missing safe misuse diagnostic")
		}
	}
}
