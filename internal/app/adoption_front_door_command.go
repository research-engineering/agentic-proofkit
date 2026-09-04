package app

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
)

type adoptionFrontDoorArgs struct {
	color          string
	colorExplicit  bool
	format         string
	mode           string
	repositoryRoot string
	stack          string
}

func runAdoptionFrontDoor(ctx context.Context, command string, args []string, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	options, err := parseAdoptionFrontDoorArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	inventory, err := repositoryinventory.Scan(ctx, options.repositoryRoot)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if command == "repository-inventory" {
		return writeJSON(inventory.JSONValue(), 0, nil, stdout, stderr)
	}
	plan, err := adoptionplan.Build(options.mode, inventory, options.stack)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.format == "json" {
		return writeJSON(plan.JSONValue(), 0, nil, stdout, stderr)
	}
	lines, err := adoptionplan.TextProjection(plan)
	if err != nil {
		return writeText("", 1, err, stdout, stderr)
	}
	plain, err := adoptionplan.RenderText(lines)
	if err != nil {
		return writeText("", 1, err, stdout, stderr)
	}
	view := adoptionPlanTerminalText(lines)
	output, err := renderTerminalText(view, options.color, capabilities)
	if err == nil && options.color == "never" && output != plain {
		err = fmt.Errorf("adoption plan text projection drifted")
	}
	return writeText(output, 0, err, stdout, stderr)
}

func parseAdoptionFrontDoorArgs(command string, args []string) (adoptionFrontDoorArgs, error) {
	options := adoptionFrontDoorArgs{color: "never", format: "json"}
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		flag := args[index]
		if !adoptionFrontDoorFlagAllowed(command, flag) {
			return adoptionFrontDoorArgs{}, fmt.Errorf("unsupported argument for %s: %s", commandRouteForDiagnostic(command), flag)
		}
		if seen[flag] {
			return adoptionFrontDoorArgs{}, fmt.Errorf("%s may be specified only once", flag)
		}
		seen[flag] = true
		if index+1 >= len(args) || args[index+1] == "" {
			return adoptionFrontDoorArgs{}, missingAdoptionFrontDoorValue(flag)
		}
		value := args[index+1]
		index++
		switch flag {
		case "--repo-root":
			options.repositoryRoot = value
		case "--color":
			if value != "auto" && value != "never" {
				return adoptionFrontDoorArgs{}, fmt.Errorf("--color requires one of: auto, never")
			}
			options.color = value
			options.colorExplicit = true
		case "--format":
			if value != "json" && value != "text" {
				return adoptionFrontDoorArgs{}, fmt.Errorf("--format requires one of: json, text")
			}
			options.format = value
		case "--mode":
			if value != adoptionplan.IntentFresh && value != adoptionplan.IntentCodeBaseline && value != adoptionplan.IntentAuditFromCode {
				return adoptionFrontDoorArgs{}, fmt.Errorf("--mode requires one of: audit-from-code, code-baseline, fresh")
			}
			options.mode = value
		case "--stack":
			if !stackpreset.IsPresetID(value) {
				return adoptionFrontDoorArgs{}, fmt.Errorf("--stack requires one of: %s", strings.Join(stackpreset.IDs(), ", "))
			}
			options.stack = value
		}
	}
	if options.repositoryRoot == "" {
		return adoptionFrontDoorArgs{}, fmt.Errorf("%s requires --repo-root <path>", commandRouteForDiagnostic(command))
	}
	if command == "adopt-plan" && options.mode == "" {
		return adoptionFrontDoorArgs{}, fmt.Errorf("adopt plan requires --mode <fresh|code-baseline|audit-from-code>")
	}
	if options.colorExplicit && options.format != "text" {
		return adoptionFrontDoorArgs{}, fmt.Errorf("--color is valid only with --format text")
	}
	return options, nil
}

func adoptionFrontDoorFlagAllowed(command, flag string) bool {
	if flag == "--repo-root" {
		return true
	}
	if command != "adopt-plan" {
		return false
	}
	switch flag {
	case "--color", "--format", "--mode", "--stack":
		return true
	default:
		return false
	}
}

func missingAdoptionFrontDoorValue(flag string) error {
	switch flag {
	case "--color":
		return fmt.Errorf("--color requires one of: auto, never")
	case "--format":
		return fmt.Errorf("--format requires one of: json, text")
	case "--mode":
		return fmt.Errorf("--mode requires one of: audit-from-code, code-baseline, fresh")
	case "--repo-root":
		return fmt.Errorf("--repo-root requires a path")
	case "--stack":
		return fmt.Errorf("--stack requires a preset id")
	default:
		return fmt.Errorf("unsupported adoption front-door argument")
	}
}

func commandRouteForDiagnostic(command string) string {
	descriptor, ok := commandDescriptorFor(command)
	if !ok {
		return command
	}
	return commandRouteText(descriptor.routeTokens)
}

func adoptionPlanTerminalText(lines []adoptionplan.TextLine) terminalText {
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
