package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofbindingtestinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runTestEvidenceInventory(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseTestEvidenceInventoryArgs(args)
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
	if options.normalizedInventory {
		if options.projection == "proof-binding-derived" {
			output, exitCode, err := proofbindingtestinventory.BuildNormalized(input)
			if err != nil {
				writeDiagnostic(stderr, err)
				return 1
			}
			return writeJSON(output, exitCode, nil, stdout, stderr)
		}
		output, exitCode, err := testevidenceinventory.BuildNormalized(input)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		return writeJSON(output, exitCode, nil, stdout, stderr)
	}
	if options.projection == "proof-binding-derived" {
		record, exitCode, err := proofbindingtestinventory.BuildReport(input)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		return writeJSON(record.JSONValue(), exitCode, nil, stdout, stderr)
	}
	record, exitCode, err := testevidenceinventory.Build(input)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return writeJSON(record.JSONValue(), exitCode, nil, stdout, stderr)
}

func parseTestEvidenceInventoryArgs(args []string) (testEvidenceInventoryArgs, error) {
	options := testEvidenceInventoryArgs{}
	inputPointerSeen := false
	projectionSeen := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return testEvidenceInventoryArgs{}, fmt.Errorf("test-evidence-inventory requires --input <path|->")
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointerSeen || index+1 >= len(args) {
				return testEvidenceInventoryArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointerSeen = true
			options.inputPointer = args[index+1]
			index++
		case "--normalized-inventory":
			if options.normalizedInventory {
				return testEvidenceInventoryArgs{}, fmt.Errorf("test-evidence-inventory accepts --normalized-inventory at most once")
			}
			options.normalizedInventory = true
		case "--projection":
			if projectionSeen || index+1 >= len(args) || args[index+1] == "" {
				return testEvidenceInventoryArgs{}, fmt.Errorf("test-evidence-inventory --projection requires proof-binding-derived")
			}
			projectionSeen = true
			if args[index+1] != "proof-binding-derived" {
				return testEvidenceInventoryArgs{}, fmt.Errorf("test-evidence-inventory --projection must be proof-binding-derived")
			}
			options.projection = args[index+1]
			index++
		default:
			return testEvidenceInventoryArgs{}, fmt.Errorf("unsupported argument for test-evidence-inventory: %s", args[index])
		}
	}
	if options.inputPath == "" {
		return testEvidenceInventoryArgs{}, fmt.Errorf("test-evidence-inventory requires --input <path|->")
	}
	return options, nil
}
