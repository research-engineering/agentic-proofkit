package app

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

type agentWorkflowArgs struct {
	inputPath      string
	inputPointer   jsonpointer.Pointer
	pointerPresent bool
	format         string
	color          string
	colorExplicit  bool
	agentEnvelope  bool
}

func parseAgentWorkflowArgs(command string, args []string) (agentWorkflowArgs, error) {
	options := agentWorkflowArgs{format: "json", color: "never"}
	diagnosticRoute := commandRouteForDiagnostic(command)
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch argument {
		case "--agent-envelope":
			if command != "change-workflow-plan" {
				return agentWorkflowArgs{}, fmt.Errorf("unsupported argument for %s: %s", diagnosticRoute, argument)
			}
			if seen[argument] {
				return agentWorkflowArgs{}, fmt.Errorf("%s may be specified only once", argument)
			}
			seen[argument] = true
			options.agentEnvelope = true
		case "--color", "--format", "--input", "--input-pointer":
			if command == "native-evidence-guidance" && (argument == "--input" || argument == "--input-pointer") {
				return agentWorkflowArgs{}, fmt.Errorf("unsupported argument for %s: %s", diagnosticRoute, argument)
			}
			if seen[argument] {
				return agentWorkflowArgs{}, fmt.Errorf("%s may be specified only once", argument)
			}
			if index+1 >= len(args) || args[index+1] == "" && argument != "--input-pointer" {
				return agentWorkflowArgs{}, missingAgentWorkflowValue(diagnosticRoute, argument)
			}
			seen[argument] = true
			value := args[index+1]
			index++
			switch argument {
			case "--color":
				if value != "auto" && value != "never" {
					return agentWorkflowArgs{}, fmt.Errorf("--color requires one of: auto, never")
				}
				options.color = value
				options.colorExplicit = true
			case "--format":
				if value != "json" && value != "text" {
					return agentWorkflowArgs{}, fmt.Errorf("--format requires one of: json, text")
				}
				options.format = value
			case "--input":
				options.inputPath = value
			case "--input-pointer":
				pointer, err := jsonpointer.Parse(value)
				if err != nil {
					return agentWorkflowArgs{}, err
				}
				options.inputPointer = pointer
				options.pointerPresent = true
			}
		default:
			return agentWorkflowArgs{}, fmt.Errorf("unsupported argument for %s: %s", diagnosticRoute, argument)
		}
	}
	if command == "change-workflow-plan" && options.inputPath == "" {
		return agentWorkflowArgs{}, fmt.Errorf("%s requires --input <path|->", diagnosticRoute)
	}
	if options.colorExplicit && options.format != "text" {
		return agentWorkflowArgs{}, fmt.Errorf("--color is valid only with --format text")
	}
	if options.agentEnvelope && options.format != "json" {
		return agentWorkflowArgs{}, fmt.Errorf("--agent-envelope is valid only with JSON output")
	}
	return options, nil
}

func missingAgentWorkflowValue(command string, flag string) error {
	switch flag {
	case "--input":
		return fmt.Errorf("%s requires --input <path|->", command)
	case "--input-pointer":
		return fmt.Errorf("--input-pointer requires a JSON pointer")
	case "--format":
		return fmt.Errorf("--format requires one of: json, text")
	case "--color":
		return fmt.Errorf("--color requires one of: auto, never")
	default:
		return fmt.Errorf("unsupported argument for %s: %s", command, flag)
	}
}
