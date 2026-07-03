package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runRequirementProofResolver(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseRequirementProofResolverArgs(args)
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
	outputValue, exitCode, err := requirementbinding.BuildResolver(input, requirementbinding.ResolverOptions{
		LocalEnvironmentClasses: options.localEnvironmentClasses,
	})
	return writeJSON(outputValue, exitCode, err, stdout, stderr)
}

func parseRequirementProofResolverArgs(args []string) (requirementProofResolverArgs, error) {
	options := requirementProofResolverArgs{}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return requirementProofResolverArgs{}, fmt.Errorf("requirement-proof-resolver requires --input <path|->")
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if index+1 >= len(args) {
				return requirementProofResolverArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			options.inputPointer = args[index+1]
			index++
		case "--local-environment-class":
			if index+1 >= len(args) || args[index+1] == "" {
				return requirementProofResolverArgs{}, fmt.Errorf("--local-environment-class requires an id")
			}
			options.localEnvironmentClasses = append(options.localEnvironmentClasses, args[index+1])
			index++
		case "--empty-local-environment-policy":
			options.emptyLocalEnvironmentPolicy = true
		default:
			return requirementProofResolverArgs{}, fmt.Errorf("unsupported argument for requirement-proof-resolver: %s", args[index])
		}
	}
	if options.inputPath == "" {
		return requirementProofResolverArgs{}, fmt.Errorf("requirement-proof-resolver requires --input <path|->")
	}
	if len(options.localEnvironmentClasses) == 0 && !options.emptyLocalEnvironmentPolicy {
		return requirementProofResolverArgs{}, fmt.Errorf("requirement-proof-resolver requires --local-environment-class or --empty-local-environment-policy")
	}
	if len(options.localEnvironmentClasses) > 0 && options.emptyLocalEnvironmentPolicy {
		return requirementProofResolverArgs{}, fmt.Errorf("--local-environment-class and --empty-local-environment-policy are mutually exclusive")
	}
	return options, nil
}
