package app

import (
	"context"
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptiondoctor"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/jsonreportcliadaptersource"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

// Requirement/proof contracts for large repositories can legitimately exceed a
// small interactive payload. Keep the CLI bounded, but size the bound for
// repository-scale spec/proof graphs instead of toy fixtures.
const maxInputBytes = 32 << 20

func Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		return writeText(usage(), 0, nil, stdout, stderr)
	}
	descriptor, ok := commandDescriptorFor(args[0])
	if !ok {
		writeDiagnosticf(stderr, "unsupported command: %s", args[0])
		return 1
	}
	if isCommandHelpRequest(args) {
		return writeText(commandUsage(descriptor), 0, nil, stdout, stderr)
	}
	switch descriptor.runner {
	case commandRunnerHelp:
		if len(args) == 2 && args[1] != "--help" && args[1] != "-h" {
			target, targetOK := commandDescriptorFor(args[1])
			if !targetOK {
				writeDiagnosticf(stderr, "unsupported help target: %s", args[1])
				return 1
			}
			return writeText(commandUsage(target), 0, nil, stdout, stderr)
		}
		if len(args) != 1 && !(len(args) == 2 && (args[1] == "--help" || args[1] == "-h")) {
			_, _ = fmt.Fprintln(stderr, "help supports only --help or -h")
			return 1
		}
		return writeText(usage(), 0, nil, stdout, stderr)
	case commandRunnerInit:
		preset, err := parseInitArgs(args[1:])
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		record, err := buildInitReport(preset)
		return writeJSON(record.JSONValue(), 0, err, stdout, stderr)
	case commandRunnerAdoptionDoctor:
		return runAgentEnvelopeCommand(args[0], args[1:], stdin, stdout, stderr, agentEnvelopeBuilders{
			build:         adoptiondoctor.Build,
			buildEnvelope: adoptiondoctor.BuildEnvelope,
		})
	case commandRunnerAdoptionContractEnvelope:
		return runAdoptionContractEnvelope(args[1:], stdin, stdout, stderr)
	case commandRunnerAdoptionWorkflow:
		return runAgentEnvelopeCommand(args[0], args[1:], stdin, stdout, stderr, agentEnvelopeBuilders{
			build:                       adoptionworkflow.Build,
			buildEnvelope:               adoptionworkflow.BuildEnvelope,
			buildFromContract:           adoptionworkflow.BuildFromContractEnvelope,
			buildEnvelopeFromContract:   adoptionworkflow.BuildEnvelopeFromContractEnvelope,
			supportsContractEnvelope:    true,
			supportsMaterializationFile: false,
		})
	case commandRunnerAgentRoute:
		return runAgentRoute(args[1:], stdin, stdout, stderr)
	case commandRunnerContractEnvelope:
		return runContractEnvelopeCommand(args[0], args[1:], stdin, stdout, stderr, gradualadoption.Build, gradualadoption.BuildFromContractEnvelope)
	case commandRunnerGradualAdoptionBootstrap:
		return runGradualAdoptionBootstrap(args[1:], stdin, stdout, stderr)
	case commandRunnerGradualAdoptionGuidance:
		return runGradualAdoptionGuidance(args[1:], stdin, stdout, stderr)
	case commandRunnerJSONReportCLIAdapterSource:
		language, format, err := parseJSONReportCLIAdapterSourceArgs(args[1:])
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		output, err := jsonreportcliadaptersource.Build(language, format)
		return writeJSON(output, 0, err, stdout, stderr)
	case commandRunnerPilotAdmission:
		return runPilotAdmission(args[1:], stdin, stdout, stderr)
	case commandRunnerProjectStructure:
		return runProjectStructure(args[1:], stdin, stdout, stderr)
	case commandRunnerTypeScriptPublicAPISurfaces:
		return runTypeScriptPublicAPI(args[1:], stdin, stdout, stderr)
	case commandRunnerStackPreset:
		presetID, err := parseStackPresetArgs(args[1:])
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		record, err := stackpreset.Build(presetID)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		return writeJSON(record.JSONValue(), 0, nil, stdout, stderr)
	case commandRunnerConformanceProfile:
		return runConformanceProfile(args[1:], stdin, stdout, stderr)
	case commandRunnerRequirementProofResolver:
		return runRequirementProofResolver(args[1:], stdin, stdout, stderr)
	case commandRunnerRequirementBrowserServer:
		return runRequirementBrowserServer(ctx, args[1:], stdin, stdout, stderr)
	case commandRunnerRequirementView:
		return runRequirementView(args[0], args[1:], stdin, stdout, stderr)
	case commandRunnerTestEvidenceInventory:
		return runTestEvidenceInventory(args[1:], stdin, stdout, stderr)
	case commandRunnerPlanning:
		return runPlanningCommand(args[0], args[1:], stdin, stdout, stderr)
	case commandRunnerGenericInput:
		return runGenericInputCommand(args[0], args[1:], stdin, stdout, stderr)
	default:
		writeDiagnosticf(stderr, "unsupported command runner: %s", descriptor.runner)
		return 1
	}
}

func runGenericInputCommand(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	inputPath, inputPointer, err := parseInputOnlyArgs(command, args)
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
	outputValue, exitCode, err := buildOutput(command, input)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return writeJSON(outputValue, exitCode, nil, stdout, stderr)
}

type conformanceProfileArgs struct {
	format       string
	inputPath    string
	inputPointer string
	list         bool
	profileID    string
	verify       bool
}

type requirementProofResolverArgs struct {
	emptyLocalEnvironmentPolicy bool
	inputPath                   string
	inputPointer                string
	localEnvironmentClasses     []string
}

type requirementViewArgs struct {
	agentEnvelope               bool
	emptyLocalEnvironmentPolicy bool
	format                      string
	inputPath                   string
	inputPointer                string
	localEnvironmentClasses     []string
	outputPath                  string
	scope                       string
}

type requirementBrowserArgs struct {
	emptyLocalEnvironmentPolicy bool
	host                        string
	inputPath                   string
	inputPointer                string
	localEnvironmentClasses     []string
	open                        bool
	port                        int
	portSet                     bool
	scope                       string
	serve                       bool
	view                        string
}

type planningArgs struct {
	agentEnvelope bool
	inputPath     string
	inputPointer  string
}

type testEvidenceInventoryArgs struct {
	inputPath           string
	inputPointer        string
	normalizedInventory bool
	projection          string
}

type pilotAdmissionArgs struct {
	contractEnvelope bool
	inputPath        string
	inputPointer     string
	pilot            string
}

type adoptionContractArgs struct {
	agentEnvelope           bool
	checkedScope            string
	guidanceMode            string
	inputPath               string
	materializationManifest bool
	mode                    string
	pilot                   string
	pilotSet                bool
	touchedRuleIDs          []string
}

type publicAPIArgs struct {
	inputPath    string
	inputPointer string
	repoRoot     string
}

type envelopeCommandArgs struct {
	agentEnvelope    bool
	checkedScope     string
	contractEnvelope bool
	guidanceMode     string
	inputPath        string
	inputPointer     string
	materialization  bool
	touchedRuleIDs   []string
}

type buildJSONFunc func(any) (map[string]any, int, error)

type agentEnvelopeBuilders struct {
	build                       buildJSONFunc
	buildEnvelope               buildJSONFunc
	buildFromContract           buildJSONFunc
	buildEnvelopeFromContract   buildJSONFunc
	supportsContractEnvelope    bool
	supportsMaterializationFile bool
}
