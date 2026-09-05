package app

import (
	"fmt"
	"strings"
)

const (
	ansiReset = "\x1b[0m"
	ansiLabel = "\x1b[1;36m"
)

// PresentationCapabilities are immutable process-boundary facts. Library
// callers use the zero value, which never emits terminal control sequences.
type PresentationCapabilities struct {
	StdoutIsTTY    bool
	NoColorPresent bool
}

type terminalTokenKind string

const (
	terminalTokenPlain terminalTokenKind = "plain"
	terminalTokenLabel terminalTokenKind = "label"
)

type terminalTextToken struct {
	kind terminalTokenKind
	text string
}

type terminalText struct {
	tokens []terminalTextToken
}

func newTerminalText(tokens ...terminalTextToken) terminalText {
	return terminalText{tokens: append([]terminalTextToken(nil), tokens...)}
}

func labeledTerminalText(plain string) terminalText {
	lines := strings.SplitAfter(plain, "\n")
	tokens := make([]terminalTextToken, 0, len(lines)*2)
	for _, line := range lines {
		if line == "" {
			continue
		}
		content := strings.TrimSuffix(line, "\n")
		newline := strings.TrimPrefix(line, content)
		if strings.HasPrefix(content, "- ") {
			tokens = append(tokens, terminalTextToken{kind: terminalTokenPlain, text: line})
			continue
		}
		separator := strings.IndexByte(content, ':')
		if separator < 0 {
			tokens = append(tokens,
				terminalTextToken{kind: terminalTokenLabel, text: content},
				terminalTextToken{kind: terminalTokenPlain, text: newline},
			)
			continue
		}
		tokens = append(tokens,
			terminalTextToken{kind: terminalTokenLabel, text: content[:separator]},
			terminalTextToken{kind: terminalTokenPlain, text: content[separator:] + newline},
		)
	}
	return newTerminalText(tokens...)
}

func renderTerminalText(value terminalText, colorMode string, capabilities PresentationCapabilities) (string, error) {
	useANSI := colorMode == "auto" && capabilities.StdoutIsTTY && !capabilities.NoColorPresent
	if colorMode != "never" && colorMode != "auto" {
		return "", fmt.Errorf("unsupported color mode")
	}
	var builder strings.Builder
	for _, token := range value.tokens {
		style, err := terminalTokenStyle(token.kind)
		if err != nil {
			return "", err
		}
		if useANSI && style != "" && token.text != "" {
			builder.WriteString(style)
			builder.WriteString(token.text)
			builder.WriteString(ansiReset)
			continue
		}
		builder.WriteString(token.text)
	}
	return builder.String(), nil
}

func terminalTokenStyle(kind terminalTokenKind) (string, error) {
	switch kind {
	case terminalTokenPlain:
		return "", nil
	case terminalTokenLabel:
		return ansiLabel, nil
	default:
		return "", fmt.Errorf("unsupported terminal token kind")
	}
}
