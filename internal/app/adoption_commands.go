package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptioncontract"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/projectstructure"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func runAdoptionContractEnvelope(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseAdoptionContractArgs(args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	input, err := readInput(options.inputPath, stdin)
	if err != nil {
		if options.agentEnvelope {
			return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
		}
		writeDiagnostic(stderr, err)
		return 1
	}
	output, exitCode, err := adoptioncontract.Build(input, adoptioncontract.Options{
		AgentEnvelope:           options.agentEnvelope,
		MaterializationManifest: options.materializationManifest,
		Mode:                    options.mode,
		Pilot:                   options.explicitPilot(),
		Guidance: gradualadoption.GuidanceOptions{
			CheckedScope:   options.checkedScope,
			GuidanceMode:   options.guidanceMode,
			TouchedRuleIDs: options.touchedRuleIDs,
		},
	})
	if err != nil && options.agentEnvelope {
		return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
	}
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func (options adoptionContractArgs) explicitPilot() string {
	if !options.pilotSet {
		return ""
	}
	return options.pilot
}

func parseAdoptionContractArgs(args []string) (adoptionContractArgs, error) {
	options := adoptionContractArgs{pilot: "first"}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return adoptionContractArgs{}, fmt.Errorf("adoption-contract-envelope requires --input <path|->")
			}
			options.inputPath = args[index+1]
			index++
		case "--mode":
			if index+1 >= len(args) || args[index+1] == "" {
				return adoptionContractArgs{}, fmt.Errorf("--mode requires adoption, bootstrap, guidance, pilot, or workflow")
			}
			mode := args[index+1]
			if mode != "adoption" && mode != "bootstrap" && mode != "guidance" && mode != "pilot" && mode != "workflow" {
				return adoptionContractArgs{}, fmt.Errorf("--mode requires adoption, bootstrap, guidance, pilot, or workflow")
			}
			options.mode = mode
			index++
		case "--agent-envelope":
			options.agentEnvelope = true
		case "--materialization-manifest":
			options.materializationManifest = true
		case "--pilot":
			if index+1 >= len(args) {
				return adoptionContractArgs{}, fmt.Errorf("--pilot requires first, stack-diverse, or all")
			}
			pilot := args[index+1]
			if pilot != "first" && pilot != "stack-diverse" && pilot != "all" {
				return adoptionContractArgs{}, fmt.Errorf("--pilot requires first, stack-diverse, or all")
			}
			options.pilot = pilot
			options.pilotSet = true
			index++
		case "--guidance-mode":
			if index+1 >= len(args) {
				return adoptionContractArgs{}, fmt.Errorf("--guidance-mode requires %s", adoptionmode.CLIAllowedText())
			}
			mode, err := adoptionmode.ValidateCLI(args[index+1], "--guidance-mode")
			if err != nil {
				return adoptionContractArgs{}, err
			}
			options.guidanceMode = mode
			index++
		case "--checked-scope":
			if index+1 >= len(args) {
				return adoptionContractArgs{}, fmt.Errorf("--checked-scope requires %s", adoptionmode.CLIScopeText())
			}
			scope, err := adoptionmode.ValidateScopeCLI(args[index+1], "--checked-scope")
			if err != nil {
				return adoptionContractArgs{}, err
			}
			options.checkedScope = scope
			index++
		case "--touched-rule-id":
			if index+1 >= len(args) || args[index+1] == "" {
				return adoptionContractArgs{}, fmt.Errorf("--touched-rule-id requires a rule id")
			}
			options.touchedRuleIDs = append(options.touchedRuleIDs, args[index+1])
			index++
		default:
			return adoptionContractArgs{}, fmt.Errorf("unsupported argument for adoption-contract-envelope: %s", args[index])
		}
	}
	if options.inputPath == "" {
		return adoptionContractArgs{}, fmt.Errorf("adoption-contract-envelope requires --input <path|->")
	}
	if options.mode == "" {
		return adoptionContractArgs{}, fmt.Errorf("--mode requires adoption, bootstrap, guidance, pilot, or workflow")
	}
	if options.agentEnvelope && options.mode != "workflow" && options.mode != "bootstrap" && options.mode != "guidance" {
		return adoptionContractArgs{}, fmt.Errorf("--agent-envelope is valid only for workflow, bootstrap, or guidance modes")
	}
	if options.materializationManifest && options.mode != "bootstrap" {
		return adoptionContractArgs{}, fmt.Errorf("--materialization-manifest is valid only for bootstrap mode")
	}
	if options.agentEnvelope && options.materializationManifest {
		return adoptionContractArgs{}, fmt.Errorf("--agent-envelope and --materialization-manifest are mutually exclusive")
	}
	if options.pilotSet && options.mode != "pilot" {
		return adoptionContractArgs{}, fmt.Errorf("--pilot is valid only for pilot mode")
	}
	if (options.guidanceMode != "" || options.checkedScope != "" || len(options.touchedRuleIDs) > 0) && options.mode != "guidance" {
		return adoptionContractArgs{}, fmt.Errorf("--guidance-mode, --checked-scope, and --touched-rule-id are valid only for guidance mode")
	}
	return options, nil
}

func runPilotAdmission(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parsePilotAdmissionArgs(args)
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
	if options.pilot == "all" {
		first, firstExitCode, err := pilotadmission.BuildFromContractEnvelope(input, "input", pilotadmission.Options{})
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		stackDiverse, stackDiverseExitCode, err := pilotadmission.BuildFromContractEnvelope(input, "stackDiverseInput", pilotadmission.Options{
			RequireStackDiverseReleaseCandidate: true,
		})
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		exitCode := 0
		if firstExitCode != 0 || stackDiverseExitCode != 0 {
			exitCode = 1
		}
		return writeJSON([]any{first.JSONValue(), stackDiverse.JSONValue()}, exitCode, nil, stdout, stderr)
	}
	optionsForReport := pilotadmission.Options{}
	field := "input"
	if options.pilot == "stack-diverse" {
		optionsForReport.RequireStackDiverseReleaseCandidate = true
		field = "stackDiverseInput"
	}
	var record report.Record
	var exitCode int
	if options.contractEnvelope {
		record, exitCode, err = pilotadmission.BuildFromContractEnvelope(input, field, optionsForReport)
	} else {
		record, exitCode, err = pilotadmission.Build(input, optionsForReport)
	}
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return writeJSON(record.JSONValue(), exitCode, nil, stdout, stderr)
}

func parsePilotAdmissionArgs(args []string) (pilotAdmissionArgs, error) {
	options := pilotAdmissionArgs{pilot: "first"}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return pilotAdmissionArgs{}, fmt.Errorf("pilot-admission requires --input <path|->")
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if index+1 >= len(args) {
				return pilotAdmissionArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			options.inputPointer = args[index+1]
			index++
		case "--contract-envelope":
			options.contractEnvelope = true
		case "--stack-diverse":
			options.pilot = "stack-diverse"
		case "--pilot":
			if index+1 >= len(args) {
				return pilotAdmissionArgs{}, fmt.Errorf("--pilot requires first, stack-diverse, or all")
			}
			pilot := args[index+1]
			if pilot != "first" && pilot != "stack-diverse" && pilot != "all" {
				return pilotAdmissionArgs{}, fmt.Errorf("--pilot requires first, stack-diverse, or all")
			}
			options.pilot = pilot
			index++
		default:
			return pilotAdmissionArgs{}, fmt.Errorf("unsupported argument for pilot-admission: %s", args[index])
		}
	}
	if options.inputPath == "" {
		return pilotAdmissionArgs{}, fmt.Errorf("pilot-admission requires --input <path|->")
	}
	if options.contractEnvelope && options.inputPointer != "" {
		return pilotAdmissionArgs{}, fmt.Errorf("--contract-envelope and --input-pointer are mutually exclusive")
	}
	if options.pilot == "all" && !options.contractEnvelope {
		return pilotAdmissionArgs{}, fmt.Errorf("--pilot all requires --contract-envelope")
	}
	return options, nil
}

func runProjectStructure(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parsePlanningArgs("scaffold-project-structure", args)
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
	if options.agentEnvelope {
		output, exitCode, err := projectstructure.BuildEnvelope(input)
		if err != nil {
			return writeJSON(agentenvelope.InvalidInput(diagnosticMessage(err)), 1, nil, stdout, stderr)
		}
		return writeJSON(output, exitCode, nil, stdout, stderr)
	}
	output, exitCode, err := projectstructure.Build(input)
	return writeJSON(output, exitCode, err, stdout, stderr)
}
