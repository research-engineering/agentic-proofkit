package app

import (
	"strings"
	"testing"
)

func TestTerminalStyleCapabilityRelation(t *testing.T) {
	view := newTerminalText(
		terminalTextToken{kind: terminalTokenLabel, text: "Action"},
		terminalTextToken{kind: terminalTokenPlain, text: ": inspect\n"},
		terminalTextToken{kind: terminalTokenSecondary, text: "Next"},
		terminalTextToken{kind: terminalTokenPlain, text: ": verify\n"},
	)
	plain, err := plainTerminalText(view)
	if err != nil {
		t.Fatalf("plainTerminalText() error = %v", err)
	}
	for _, test := range []struct {
		name         string
		mode         string
		capabilities PresentationCapabilities
		wantANSI     bool
	}{
		{name: "default never on tty", mode: "never", capabilities: PresentationCapabilities{StdoutIsTTY: true}},
		{name: "auto pipe", mode: "auto"},
		{name: "auto tty", mode: "auto", capabilities: PresentationCapabilities{StdoutIsTTY: true}, wantANSI: true},
		{name: "auto tty no color present", mode: "auto", capabilities: PresentationCapabilities{StdoutIsTTY: true, NoColorPresent: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := renderTerminalText(view, test.mode, test.capabilities)
			if err != nil {
				t.Fatalf("renderTerminalText() error = %v", err)
			}
			if gotANSI := strings.Contains(got, "\x1b["); gotANSI != test.wantANSI {
				t.Fatalf("ANSI presence = %t, want %t in %q", gotANSI, test.wantANSI, got)
			}
			if stripped := stripTestANSI(got); stripped != plain {
				t.Fatalf("stripped text = %q, want %q", stripped, plain)
			}
		})
	}
}

func TestTerminalStyleRejectsUnknownModesAndTokens(t *testing.T) {
	if _, err := renderTerminalText(newTerminalText(), "always", PresentationCapabilities{}); err == nil {
		t.Fatal("expected unsupported color mode error")
	}
	if _, err := renderTerminalText(newTerminalText(terminalTextToken{kind: "unknown", text: "x"}), "never", PresentationCapabilities{}); err == nil {
		t.Fatal("expected unsupported token kind error")
	}
}

func stripTestANSI(value string) string {
	for _, sequence := range []string{ansiLabel, ansiSecondary, ansiReset} {
		value = strings.ReplaceAll(value, sequence, "")
	}
	return value
}
