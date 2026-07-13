package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runRequirementContextCompose(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	inputPath, inputPointer, repoRoot, err := parseRequirementContextComposeArgs(args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	input, err := readInput(inputPath, stdin)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if inputPointer != "" {
		input, err = jsonpointer.Select(input, inputPointer)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	output, err := requirementcontext.Compose(repoRoot, input)
	return writeJSON(output, 0, err, stdout, stderr)
}

func parseRequirementContextComposeArgs(args []string) (string, string, string, error) {
	inputPath := ""
	inputPointer := ""
	repoRoot := ""
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return "", "", "", fmt.Errorf("requirement-context-compose requires --input <path|->")
			}
			inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointer != "" || index+1 >= len(args) {
				return "", "", "", fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointer = args[index+1]
			index++
		case "--repo-root":
			if repoRoot != "" || index+1 >= len(args) || args[index+1] == "" {
				return "", "", "", fmt.Errorf("--repo-root requires a path")
			}
			repoRoot = args[index+1]
			index++
		default:
			return "", "", "", fmt.Errorf("unsupported argument for requirement-context-compose: %s", args[index])
		}
	}
	if inputPath == "" || repoRoot == "" {
		return "", "", "", fmt.Errorf("requirement-context-compose requires --input <path|-> and --repo-root <path>")
	}
	return inputPath, inputPointer, repoRoot, nil
}
