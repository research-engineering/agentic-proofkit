package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runAgentEnvelopeCommand(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, builders agentEnvelopeBuilders) int {
	options, err := parseEnvelopeCommandArgs(command, args, builders)
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
	if options.agentEnvelope && options.contractEnvelope {
		output, exitCode, err := builders.buildEnvelopeFromContract(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.agentEnvelope {
		output, exitCode, err := builders.buildEnvelope(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.contractEnvelope {
		output, exitCode, err := builders.buildFromContract(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := builders.build(input)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func runGradualAdoptionGuidance(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseEnvelopeCommandArgs("gradual-adoption-guidance", args, agentEnvelopeBuilders{
		supportsContractEnvelope: true,
	})
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
	guidanceOptions := gradualadoption.GuidanceOptions{
		CheckedScope:   options.checkedScope,
		GuidanceMode:   options.guidanceMode,
		TouchedRuleIDs: options.touchedRuleIDs,
	}
	if options.agentEnvelope && options.contractEnvelope {
		output, exitCode, err := gradualadoption.BuildGuidanceEnvelopeFromContractEnvelope(input, guidanceOptions)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.agentEnvelope {
		output, exitCode, err := gradualadoption.BuildGuidanceEnvelope(input, guidanceOptions)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.contractEnvelope {
		output, exitCode, err := gradualadoption.BuildGuidanceFromContractEnvelope(input, guidanceOptions)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := gradualadoption.BuildGuidance(input, guidanceOptions)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func runGradualAdoptionBootstrap(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseEnvelopeCommandArgs("gradual-adoption-bootstrap", args, agentEnvelopeBuilders{
		supportsContractEnvelope:    true,
		supportsMaterializationFile: true,
	})
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
	if options.agentEnvelope && options.contractEnvelope {
		output, exitCode, err := gradualadoption.BuildBootstrapEnvelopeFromContractEnvelope(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.agentEnvelope {
		output, exitCode, err := gradualadoption.BuildBootstrapEnvelope(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.materialization && options.contractEnvelope {
		output, exitCode, err := gradualadoption.BuildBootstrapMaterializationManifestFromContractEnvelope(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.materialization {
		output, exitCode, err := gradualadoption.BuildBootstrapMaterializationManifest(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	if options.contractEnvelope {
		output, exitCode, err := gradualadoption.BuildBootstrapFromContractEnvelope(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := gradualadoption.BuildBootstrap(input)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func runContractEnvelopeCommand(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, build buildJSONFunc, buildFromContract buildJSONFunc) int {
	options, err := parseEnvelopeCommandArgs(command, args, agentEnvelopeBuilders{
		supportsContractEnvelope: true,
	})
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.agentEnvelope {
		_, _ = fmt.Fprintf(stderr, "--agent-envelope is valid only for %s\n", agentEnvelopeCommandList())
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
	if options.contractEnvelope {
		output, exitCode, err := buildFromContract(input)
		return writeJSON(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := build(input)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func parseEnvelopeCommandArgs(command string, args []string, builders agentEnvelopeBuilders) (envelopeCommandArgs, error) {
	options := envelopeCommandArgs{}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return envelopeCommandArgs{}, fmt.Errorf("%s requires --input <path|->", command)
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if index+1 >= len(args) {
				return envelopeCommandArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			options.inputPointer = args[index+1]
			index++
		case "--contract-envelope":
			if !builders.supportsContractEnvelope {
				return envelopeCommandArgs{}, fmt.Errorf("--contract-envelope is valid only for %s", contractEnvelopeCommandList())
			}
			options.contractEnvelope = true
		case "--agent-envelope":
			options.agentEnvelope = true
		case "--guidance-mode":
			if command != "gradual-adoption-guidance" {
				return envelopeCommandArgs{}, fmt.Errorf("--guidance-mode, --checked-scope, and --touched-rule-id are valid only for gradual-adoption-guidance")
			}
			if index+1 >= len(args) {
				return envelopeCommandArgs{}, fmt.Errorf("--guidance-mode requires %s", adoptionmode.CLIAllowedText())
			}
			mode, err := adoptionmode.ValidateCLI(args[index+1], "--guidance-mode")
			if err != nil {
				return envelopeCommandArgs{}, err
			}
			options.guidanceMode = mode
			index++
		case "--checked-scope":
			if command != "gradual-adoption-guidance" {
				return envelopeCommandArgs{}, fmt.Errorf("--guidance-mode, --checked-scope, and --touched-rule-id are valid only for gradual-adoption-guidance")
			}
			if index+1 >= len(args) {
				return envelopeCommandArgs{}, fmt.Errorf("--checked-scope requires %s", adoptionmode.CLIScopeText())
			}
			scope, err := adoptionmode.ValidateScopeCLI(args[index+1], "--checked-scope")
			if err != nil {
				return envelopeCommandArgs{}, err
			}
			options.checkedScope = scope
			index++
		case "--touched-rule-id":
			if command != "gradual-adoption-guidance" {
				return envelopeCommandArgs{}, fmt.Errorf("--guidance-mode, --checked-scope, and --touched-rule-id are valid only for gradual-adoption-guidance")
			}
			if index+1 >= len(args) || args[index+1] == "" {
				return envelopeCommandArgs{}, fmt.Errorf("--touched-rule-id requires a rule id")
			}
			options.touchedRuleIDs = append(options.touchedRuleIDs, args[index+1])
			index++
		case "--materialization-manifest":
			if !builders.supportsMaterializationFile {
				return envelopeCommandArgs{}, fmt.Errorf("--materialization-manifest is valid only for gradual-adoption-bootstrap")
			}
			options.materialization = true
		default:
			return envelopeCommandArgs{}, fmt.Errorf("unsupported argument for %s: %s", command, args[index])
		}
	}
	if options.inputPath == "" {
		return envelopeCommandArgs{}, fmt.Errorf("%s requires --input <path|->", command)
	}
	if options.contractEnvelope && options.inputPointer != "" {
		return envelopeCommandArgs{}, fmt.Errorf("--contract-envelope and --input-pointer are mutually exclusive")
	}
	if options.agentEnvelope && options.materialization {
		return envelopeCommandArgs{}, fmt.Errorf("--agent-envelope and --materialization-manifest are mutually exclusive")
	}
	if (options.guidanceMode != "" || options.checkedScope != "" || len(options.touchedRuleIDs) > 0) && !options.contractEnvelope {
		return envelopeCommandArgs{}, fmt.Errorf("guidance override flags require --contract-envelope")
	}
	return options, nil
}
