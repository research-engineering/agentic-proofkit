package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runPlanningCommand(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parsePlanningArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	input, err := readInput(options.inputPath, stdin)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.inputPointer != "" {
		input, err = jsonpointer.Select(input, options.inputPointer)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	switch command {
	case "changed-path-set":
		return runChangedPathSetPlanning(input, options, stdout, stderr)
	case "obligation-decision":
		return runObligationDecisionPlanning(input, options, stdout, stderr)
	case "selective-gate-plan", "selective-gate-evidence", "selective-gate-obligation-decision-input":
		return runSelectivePlanning(command, input, options, stdout, stderr)
	case "workspace-changed-package-plan", "workspace-shard-partition":
		return runWorkspacePlanning(command, input, options, stdout, stderr)
	default:
		writeDiagnostic(stderr, fmt.Errorf("unsupported planning command: %s", command))
		return 1
	}
}

func isExplicitPlanningCommand(command string) bool {
	switch command {
	case "changed-path-set",
		"obligation-decision",
		"selective-gate-evidence",
		"selective-gate-obligation-decision-input",
		"selective-gate-plan",
		"workspace-changed-package-plan",
		"workspace-shard-partition":
		return true
	default:
		return false
	}
}

func parsePlanningArgs(command string, args []string) (planningArgs, error) {
	options := planningArgs{}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return planningArgs{}, fmt.Errorf("%s requires --input <path|->", command)
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if index+1 >= len(args) {
				return planningArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			options.inputPointer = args[index+1]
			index++
		case "--agent-envelope":
			options.agentEnvelope = true
		default:
			return planningArgs{}, fmt.Errorf("unsupported argument for %s: %s", command, args[index])
		}
	}
	if options.inputPath == "" {
		return planningArgs{}, fmt.Errorf("%s requires --input <path|->", command)
	}
	return options, nil
}
