package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/conformanceprofile"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runConformanceProfile(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseConformanceProfileArgs(args)
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
	if options.verify {
		record, exitCode, err := conformanceprofile.BuildVerification(input)
		return writeJSON(record.JSONValue(), exitCode, err, stdout, stderr)
	}
	if options.list {
		profiles, err := conformanceprofile.List(input)
		return writeJSON(map[string]any{"profiles": stringSliceToAny(profiles)}, 0, err, stdout, stderr)
	}
	result, err := conformanceprofile.BuildProfile(input, options.profileID)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.format == "markdown" {
		return writeText(conformanceprofile.Markdown(result.ProfileReport), result.ExitCode, nil, stdout, stderr)
	}
	return writeJSON(result.ProfileReport.JSONValue(), result.ExitCode, nil, stdout, stderr)
}

func parseConformanceProfileArgs(args []string) (conformanceProfileArgs, error) {
	options := conformanceProfileArgs{format: "json"}
	inputSeen := false
	inputPointerSeen := false
	formatSeen := false
	profileSeen := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if inputSeen || index+1 >= len(args) || args[index+1] == "" {
				return conformanceProfileArgs{}, fmt.Errorf("--input requires a path")
			}
			inputSeen = true
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointerSeen || index+1 >= len(args) {
				return conformanceProfileArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointerSeen = true
			options.inputPointer = args[index+1]
			index++
		case "--verify":
			if options.verify {
				return conformanceProfileArgs{}, fmt.Errorf("--verify may be provided at most once")
			}
			options.verify = true
		case "--list":
			if options.list {
				return conformanceProfileArgs{}, fmt.Errorf("--list may be provided at most once")
			}
			options.list = true
		case "--profile":
			if profileSeen || index+1 >= len(args) || args[index+1] == "" {
				return conformanceProfileArgs{}, fmt.Errorf("--profile requires an id")
			}
			profileSeen = true
			options.profileID = args[index+1]
			index++
		case "--format":
			if formatSeen || index+1 >= len(args) || (args[index+1] != "json" && args[index+1] != "markdown") {
				return conformanceProfileArgs{}, fmt.Errorf("--format must be json or markdown")
			}
			formatSeen = true
			options.format = args[index+1]
			index++
		default:
			return conformanceProfileArgs{}, fmt.Errorf("unsupported argument: %s", args[index])
		}
	}
	if options.inputPath == "" {
		return conformanceProfileArgs{}, fmt.Errorf("--input is required")
	}
	modeCount := 0
	if options.verify {
		modeCount++
	}
	if options.list {
		modeCount++
	}
	if options.profileID != "" {
		modeCount++
	}
	if modeCount != 1 {
		return conformanceProfileArgs{}, fmt.Errorf("conformance-profile requires exactly one of --verify, --list, or --profile <id>")
	}
	if options.format != "json" && options.profileID == "" {
		return conformanceProfileArgs{}, fmt.Errorf("--format markdown is valid only with --profile <id>")
	}
	return options, nil
}
