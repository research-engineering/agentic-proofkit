package app

import (
	"context"
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
)

type projectStatusArgs struct {
	color          string
	format         string
	repositoryRoot string
}

func runProjectStatus(ctx context.Context, command string, args []string, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	options, err := parseProjectStatusArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	status, err := projectstatus.Inspect(ctx, options.repositoryRoot)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return projectStatusResult(command, options, status, stdout, stderr, capabilities)
}

func projectStatusResult(command string, options projectStatusArgs, status projectstatus.Status, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	if command == "status" {
		if options.format == "json" {
			return writeJSON(status.JSONValue(), 0, nil, stdout, stderr)
		}
		lines, err := projectstatus.StatusText(status)
		return writeProjectStatusText(lines, options.color, capabilities, stdout, stderr, err)
	}
	if command != "next" {
		writeDiagnosticf(stderr, "unsupported project status command")
		return 1
	}
	next, err := projectstatus.NextFromStatus(status)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.format == "json" {
		return writeJSON(next.JSONValue(), 0, nil, stdout, stderr)
	}
	lines, err := projectstatus.NextText(next)
	return writeProjectStatusText(lines, options.color, capabilities, stdout, stderr, err)
}

func parseProjectStatusArgs(command string, args []string) (projectStatusArgs, error) {
	options := projectStatusArgs{color: "never", format: "json"}
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		flag := args[index]
		if flag != "--color" && flag != "--format" && flag != "--repo-root" {
			return projectStatusArgs{}, fmt.Errorf("unsupported argument for %s", command)
		}
		if seen[flag] {
			return projectStatusArgs{}, fmt.Errorf("%s may be specified only once", flag)
		}
		seen[flag] = true
		if index+1 >= len(args) || args[index+1] == "" {
			return projectStatusArgs{}, missingProjectStatusValue(flag)
		}
		value := args[index+1]
		index++
		switch flag {
		case "--color":
			if value != "auto" && value != "never" {
				return projectStatusArgs{}, fmt.Errorf("--color requires one of: auto, never")
			}
			options.color = value
		case "--format":
			if value != "json" && value != "text" {
				return projectStatusArgs{}, fmt.Errorf("--format requires one of: json, text")
			}
			options.format = value
		case "--repo-root":
			options.repositoryRoot = value
		}
	}
	if options.repositoryRoot == "" {
		return projectStatusArgs{}, fmt.Errorf("%s requires --repo-root <path>", command)
	}
	if seen["--color"] && options.format != "text" {
		return projectStatusArgs{}, fmt.Errorf("--color is valid only with --format text")
	}
	return options, nil
}

func missingProjectStatusValue(flag string) error {
	switch flag {
	case "--color":
		return fmt.Errorf("--color requires one of: auto, never")
	case "--format":
		return fmt.Errorf("--format requires one of: json, text")
	case "--repo-root":
		return fmt.Errorf("--repo-root requires a path")
	default:
		return fmt.Errorf("unsupported project status argument")
	}
}

func writeProjectStatusText(lines []projectstatus.TextLine, color string, capabilities PresentationCapabilities, stdout io.Writer, stderr io.Writer, lineErr error) int {
	if lineErr != nil {
		return writeText("", 1, lineErr, stdout, stderr)
	}
	plain, err := projectstatus.RenderText(lines)
	if err != nil {
		return writeText("", 1, err, stdout, stderr)
	}
	view := projectStatusTerminalText(lines)
	output, err := renderTerminalText(view, color, capabilities)
	if err == nil && color == "never" && output != plain {
		err = fmt.Errorf("project status text projection drifted")
	}
	return writeText(output, 0, err, stdout, stderr)
}

func projectStatusTerminalText(lines []projectstatus.TextLine) terminalText {
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
