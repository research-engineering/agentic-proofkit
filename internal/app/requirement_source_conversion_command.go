package app

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceconversion"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type requirementSourceConversionArgs struct {
	inputPath    string
	inputPointer string
	target       string
	baselinePath string
	outputPath   string
}

// runRequirementSourceConversion reads each caller document once, converts the
// immutable snapshots, and publishes only a complete admitted emission.
func runRequirementSourceConversion(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	parsed, err := parseRequirementSourceConversionArgs(args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	input, err := readInput(parsed.inputPath, stdin)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if parsed.inputPointer != "" {
		input, err = jsonpointer.Select(input, parsed.inputPointer)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	var document map[string]any
	if parsed.target == requirementsourceconversion.TargetFlat {
		document, err = requirementsourceconversion.ExportFlat(input)
	} else {
		baseline, readErr := readInput(parsed.baselinePath, nil)
		if readErr != nil {
			writeDiagnostic(stderr, fmt.Errorf("requirement-source-conversion could not read --baseline: %w", readErr))
			return 1
		}
		document, err = requirementsourceconversion.ImportFlat(input, baseline)
	}
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	encoded, err := stablejson.MarshalLayout(document, jsonLayoutFromWriter(stdout))
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	// Every emission stays re-admissible through the same CLI input bound.
	if len(encoded) > maxInputBytes {
		writeDiagnosticf(stderr, "requirement source conversion refused output: output_limit_exceeded (%d bytes exceed the %d-byte input bound)", len(encoded), maxInputBytes)
		return 1
	}
	if parsed.outputPath == "" {
		if err := writeAll(stdout, encoded); err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		return 0
	}
	if err := writeNewRepoRelativeOutputFile(filepath.FromSlash(parsed.outputPath), encoded); err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return 0
}

// Descriptor validation has already admitted flag names, choices, required and
// conditional flags and single occurrences; this parser binds values and
// admits paths before any input is read.
func parseRequirementSourceConversionArgs(args []string) (requirementSourceConversionArgs, error) {
	parsed := requirementSourceConversionArgs{}
	for index := 0; index < len(args); index++ {
		flag := args[index]
		switch flag {
		case "--input", "--input-pointer", "--to", "--baseline", "--output":
		default:
			return requirementSourceConversionArgs{}, fmt.Errorf("unsupported argument for requirement-source-conversion: %s", flag)
		}
		if index+1 >= len(args) {
			return requirementSourceConversionArgs{}, fmt.Errorf("%s requires a value", flag)
		}
		value := args[index+1]
		index++
		switch flag {
		case "--input":
			parsed.inputPath = value
		case "--input-pointer":
			parsed.inputPointer = value
		case "--to":
			parsed.target = value
		case "--baseline":
			if value == "" || value == "-" {
				return requirementSourceConversionArgs{}, fmt.Errorf("--baseline requires a grouped source file path; stdin is reserved for --input")
			}
			parsed.baselinePath = value
		case "--output":
			if value == "" || value == "-" {
				return requirementSourceConversionArgs{}, fmt.Errorf("--output requires a repository-relative POSIX path other than -")
			}
			outputPath, err := admitPresentationOutputPath(value, "requirement-source-conversion output")
			if err != nil {
				return requirementSourceConversionArgs{}, err
			}
			parsed.outputPath = outputPath
		}
	}
	if parsed.inputPath == "" {
		return requirementSourceConversionArgs{}, fmt.Errorf("requirement-source-conversion requires --input <path|->")
	}
	return parsed, nil
}
