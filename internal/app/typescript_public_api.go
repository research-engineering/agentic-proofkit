package app

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/command/publicapi"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runTypeScriptPublicAPI(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parsePublicAPIArgs(args)
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
	repoRoot, err := filepath.EvalSymlinks(options.repoRoot)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	output, exitCode, err := publicapi.Verify(input, publicapi.Options{RepoRoot: repoRoot})
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func parsePublicAPIArgs(args []string) (publicAPIArgs, error) {
	options := publicAPIArgs{}
	inputPointerSeen := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return publicAPIArgs{}, fmt.Errorf("typescript-public-api-surfaces requires --input <path|->")
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointerSeen || index+1 >= len(args) {
				return publicAPIArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointerSeen = true
			options.inputPointer = args[index+1]
			index++
		case "--repo-root":
			if options.repoRoot != "" || index+1 >= len(args) || args[index+1] == "" {
				return publicAPIArgs{}, fmt.Errorf("typescript-public-api-surfaces requires --repo-root <path>")
			}
			options.repoRoot = args[index+1]
			index++
		default:
			return publicAPIArgs{}, fmt.Errorf("unsupported argument for typescript-public-api-surfaces: %s", args[index])
		}
	}
	if options.inputPath == "" {
		return publicAPIArgs{}, fmt.Errorf("typescript-public-api-surfaces requires --input <path|->")
	}
	if options.repoRoot == "" {
		return publicAPIArgs{}, fmt.Errorf("typescript-public-api-surfaces requires --repo-root <path>")
	}
	return options, nil
}
