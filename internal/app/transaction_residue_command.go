package app

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/transactionresidue"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type transactionResidueArgs struct {
	root, expectedObservation, format, color string
}

func runTransactionResidue(ctx context.Context, command string, args []string, stdout, stderr io.Writer, presentation PresentationCapabilities) int {
	options, err := parseTransactionResidueArgs(command, args)
	if err != nil {
		return writeJSON(nil, 1, err, stdout, stderr)
	}
	var output transactionresidue.Output
	if command == "transaction-inspect-residue" {
		output, err = transactionresidue.Inspect(ctx, options.root)
	} else {
		output, err = transactionresidue.Quarantine(ctx, options.root, options.expectedObservation)
	}
	if err != nil || options.format == "json" {
		return writeJSON(output.JSONValue(), 0, err, stdout, stderr)
	}
	text, err := renderTerminalText(labeledTerminalText(output.Text()), options.color, presentation)
	return writeText(text, 0, err, stdout, stderr)
}

func parseTransactionResidueArgs(command string, args []string) (transactionResidueArgs, error) {
	descriptor, exists := commandDescriptorByName[command]
	if !exists || descriptor.runner != commandRunnerTransactionResidue {
		return transactionResidueArgs{}, fmt.Errorf("unsupported transaction residue command")
	}
	values := map[string]string{"--format": "json", "--color": "never"}
	seen := map[string]bool{}
	for index := 0; index < len(args); index += 2 {
		flag := args[index]
		if !slices.Contains(descriptor.allowedFlags, flag) {
			return transactionResidueArgs{}, fmt.Errorf("unsupported transaction residue argument")
		}
		if seen[flag] || index+1 >= len(args) || args[index+1] == "" {
			return transactionResidueArgs{}, fmt.Errorf("transaction residue arguments require one non-empty value per flag")
		}
		value := args[index+1]
		if choices := descriptor.flagValueChoices[flag]; len(choices) > 0 && !slices.Contains(choices, value) {
			return transactionResidueArgs{}, fmt.Errorf("transaction residue flag value is unsupported")
		}
		if flag == "--expect-observation" {
			canonical, err := admit.SHA256Ref(value, "preparation residue observation")
			if err != nil || canonical != value {
				return transactionResidueArgs{}, fmt.Errorf("preparation residue observation must be a canonical sha256 digest reference")
			}
		}
		seen[flag], values[flag] = true, value
	}
	for _, flag := range descriptor.requiredFlags {
		if !seen[flag] {
			return transactionResidueArgs{}, fmt.Errorf("transaction residue requires %s", flag)
		}
	}
	if seen["--color"] && values["--format"] != "text" {
		return transactionResidueArgs{}, fmt.Errorf("--color is valid only with --format text")
	}
	return transactionResidueArgs{root: values["--repo-root"], expectedObservation: values["--expect-observation"], format: values["--format"], color: values["--color"]}, nil
}
