package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const cliContractPublicABISHA256 = "7a8c5c46d2f4c367bbb790f8428d28f357434287f721338a720c85b9ac28a19b"

func TestCLIContractMatchesDispatcherAndHelp(t *testing.T) {
	contract := readCLIContract(t)
	assertCLIContractSchema(t)
	if problems := commandDescriptorContractParityProblems(commandDescriptors, contract.Commands); len(problems) != 0 {
		t.Fatalf("command descriptor/contract parity problems: %v", problems)
	}
	if problems := commandDescriptorTopologyProblems(commandDescriptors); len(problems) != 0 {
		t.Fatalf("command descriptor topology problems: %v", problems)
	}
	contractCommands := map[string]struct{}{}
	commandNames := make([]string, 0, len(contract.Commands))
	for _, command := range contract.Commands {
		if _, ok := contractCommands[command.Command]; ok {
			t.Fatalf("duplicate CLI contract command: %s", command.Command)
		}
		descriptor, ok := commandDescriptorFor(command.Command)
		if !ok {
			t.Fatalf("CLI contract command %s missing private descriptor", command.Command)
		}
		contractCommands[command.Command] = struct{}{}
		commandNames = append(commandNames, command.Command)
		assertSortedUnique(t, command.AllowedFlags, command.Command+" flags")
		assertSortedUnique(t, command.OutputModes, command.Command+" output modes")
		if string(descriptor.input) != command.Input {
			t.Fatalf("%s descriptor input=%s contract input=%s", command.Command, descriptor.input, command.Input)
		}
		if string(descriptor.scopeClass) != command.ScopeClass {
			t.Fatalf("%s descriptor scopeClass=%s contract=%s", command.Command, descriptor.scopeClass, command.ScopeClass)
		}
		assertStringSet(t, descriptor.allowedFlags, command.AllowedFlags, command.Command+" descriptor flags")
		assertStringSet(t, descriptor.outputModes, command.OutputModes, command.Command+" descriptor output modes")
		if descriptor.agentEnvelope != (command.AgentEnvelope != nil && *command.AgentEnvelope) {
			t.Fatalf("%s descriptor agentEnvelope=%v contract=%v", command.Command, descriptor.agentEnvelope, command.AgentEnvelope)
		}
		if descriptor.contractEnvelope != (command.ContractEnvelope != nil && *command.ContractEnvelope) {
			t.Fatalf("%s descriptor contractEnvelope=%v contract=%v", command.Command, descriptor.contractEnvelope, command.ContractEnvelope)
		}
		if command.Input == "required" {
			if !command.Stdin || !contains(command.AllowedFlags, "--input") {
				t.Fatalf("%s required input must support stdin through --input", command.Command)
			}
			if command.InputPointer != contains(command.AllowedFlags, "--input-pointer") {
				t.Fatalf("%s inputPointer must match --input-pointer admission", command.Command)
			}
		} else if command.Stdin || command.InputPointer || contains(command.AllowedFlags, "--input") || contains(command.AllowedFlags, "--input-pointer") {
			t.Fatalf("%s no-input command must not advertise stdin or input-pointer", command.Command)
		}
		if command.AgentEnvelope != nil && *command.AgentEnvelope && !contains(command.AllowedFlags, "--agent-envelope") {
			t.Fatalf("%s agent envelope flag missing", command.Command)
		}
		if command.ContractEnvelope != nil && *command.ContractEnvelope && !contains(command.AllowedFlags, "--contract-envelope") {
			t.Fatalf("%s contract envelope flag missing", command.Command)
		}
	}
	assertSortedUnique(t, commandNames, "CLI contract commands")
	for command := range supportedCommands {
		if _, ok := contractCommands[command]; !ok {
			t.Fatalf("supported command %s missing from CLI contract", command)
		}
	}
	for command := range contractCommands {
		if _, ok := supportedCommands[command]; !ok {
			t.Fatalf("CLI contract command %s missing from dispatcher", command)
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"help"}, strings.NewReader(""), &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("help failed status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	help := stdout.String()
	for _, command := range contract.Commands {
		if command.Command == "help" {
			continue
		}
		line := helpLineForCommand(help, command.Command)
		if line == "" {
			t.Fatalf("help output does not route command %s", command.Command)
		}
		for _, flag := range command.AllowedFlags {
			if flag == "--help" || flag == "-h" {
				continue
			}
			if !strings.Contains(line, flag) {
				t.Fatalf("help line for %s missing advertised flag %s: %s", command.Command, flag, line)
			}
		}
		helpFlags := helpLineFlags(line)
		if !equalStringSets(helpFlags, command.AllowedFlags) {
			t.Fatalf("help line for %s flags=%v want %v: %s", command.Command, helpFlags, command.AllowedFlags, line)
		}
	}
	for command := range contractCommands {
		if !strings.Contains(help, "agentic-proofkit "+command) && command != "help" {
			t.Fatalf("help output does not route command %s", command)
		}
	}
}

func TestProofkitContractMapRoutesRequiredInputCommands(t *testing.T) {
	contract := readCLIContract(t)
	documentBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "proofkit-contract-map.md"))
	if err != nil {
		t.Fatalf("read proofkit contract map: %v", err)
	}
	document := string(documentBytes)
	for _, command := range contract.Commands {
		if command.Input != "required" {
			continue
		}
		if !strings.Contains(document, "`"+command.Command+"`") {
			t.Fatalf("docs/proofkit-contract-map.md does not route required-input command %s", command.Command)
		}
	}
}

func TestCLIContractPublicABIGoldenStable(t *testing.T) {
	contract := readCLIContract(t)
	commands := []any{}
	for _, command := range contract.Commands {
		record := map[string]any{
			"allowedFlags": stringsAsAny(command.AllowedFlags),
			"command":      command.Command,
			"input":        command.Input,
			"inputPointer": command.InputPointer,
			"outputModes":  stringsAsAny(command.OutputModes),
			"scopeClass":   command.ScopeClass,
			"stdin":        command.Stdin,
		}
		if command.AgentEnvelope != nil {
			record["agentEnvelope"] = *command.AgentEnvelope
		}
		if command.ContractEnvelope != nil {
			record["contractEnvelope"] = *command.ContractEnvelope
		}
		commands = append(commands, record)
	}
	abi := map[string]any{
		"commands":        commands,
		"contractId":      contract.ContractID,
		"packageName":     contract.PackageName,
		"processContract": contract.ProcessContract,
		"schemaVersion":   contract.SchemaVersion,
	}
	encoded, err := json.Marshal(abi)
	if err != nil {
		t.Fatalf("marshal CLI ABI projection: %v", err)
	}
	sum := sha256.Sum256(encoded)
	got := fmt.Sprintf("%x", sum[:])
	if got != cliContractPublicABISHA256 {
		t.Fatalf("public CLI ABI hash drifted: got %s want %s", got, cliContractPublicABISHA256)
	}
}

func TestCommandDescriptorContractParityRejectsMutations(t *testing.T) {
	contract := readCLIContract(t)
	cases := []struct {
		name        string
		descriptors []commandDescriptor
		commands    []cliContractCommand
	}{
		{
			name:        "descriptor only command",
			descriptors: append(cloneCommandDescriptors(commandDescriptors), command("descriptor-only", commandInputNone, flags("--help"), modes("text"), ownerDirs("descriptoronly"), withRunner(commandRunnerHelp))),
			commands:    contract.Commands,
		},
		{
			name:        "contract only command",
			descriptors: cloneCommandDescriptors(commandDescriptors),
			commands: append(cloneCLIContractCommands(contract.Commands), cliContractCommand{
				AllowedFlags: []string{"--help"},
				Command:      "contract-only",
				Input:        "none",
				OutputModes:  []string{"text"},
			}),
		},
		{
			name: "input drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.input = commandInputNone
			}),
			commands: contract.Commands,
		},
		{
			name: "flag drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.allowedFlags = []string{"--extra", "--input", "--input-pointer"}
			}),
			commands: contract.Commands,
		},
		{
			name: "output drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.outputModes = []string{"json", "markdown"}
			}),
			commands: contract.Commands,
		},
		{
			name: "scope class drift",
			descriptors: mutateDescriptor("typescript-public-api-surfaces", func(descriptor *commandDescriptor) {
				descriptor.scopeClass = commandScopeExplicitCallerInput
			}),
			commands: contract.Commands,
		},
		{
			name: "envelope drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.agentEnvelope = true
			}),
			commands: contract.Commands,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if problems := commandDescriptorContractParityProblems(tc.descriptors, tc.commands); len(problems) == 0 {
				t.Fatal("mutated command descriptor/contract parity was admitted")
			}
		})
	}
}

func TestCommandDescriptorTopologyRejectsInvalidRunner(t *testing.T) {
	descriptors := mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
		descriptor.runner = commandRunner("unknown_runner")
	})
	if problems := commandDescriptorTopologyProblems(descriptors); len(problems) == 0 {
		t.Fatal("descriptor with unknown runner was admitted")
	}
}

func TestCommandDescriptorTopologyRejectsInvalidScopeClass(t *testing.T) {
	descriptors := mutateDescriptor("typescript-public-api-surfaces", func(descriptor *commandDescriptor) {
		descriptor.scopeClass = commandScopeClass("unknown_scope")
	})
	if problems := commandDescriptorTopologyProblems(descriptors); len(problems) == 0 {
		t.Fatal("descriptor with unknown scope class was admitted")
	}
}

func TestCommandDescriptorTopologyRejectsImplicitPlanningRoute(t *testing.T) {
	descriptors := append(cloneCommandDescriptors(commandDescriptors), command("new-planning-command", commandInputRequired, flags("--input"), modes("json"), ownerDirs("newplanning"), withRunner(commandRunnerPlanning)))
	if problems := commandDescriptorTopologyProblems(descriptors); len(problems) == 0 {
		t.Fatal("planning runner descriptor without explicit route was admitted")
	}
}

func TestCLIContractModeSpecificPromises(t *testing.T) {
	contract := readCLIContract(t)
	commands := map[string]cliContractCommand{}
	for _, command := range contract.Commands {
		commands[command.Command] = command
	}
	assertCommand(t, commands["help"], "none", []string{"--help", "-h"}, []string{"text"})
	assertCommand(t, commands["stack-preset"], "none", []string{"--preset"}, []string{"json"})
	assertCommand(t, commands["json-report-cli-adapter-source"], "none", []string{"--format", "--language"}, []string{"json"})
	assertScopeClass(t, commands["help"], commandScopeBuiltInPackageCatalog)
	assertScopeClass(t, commands["stack-preset"], commandScopeBuiltInPackageCatalog)
	assertScopeClass(t, commands["json-report-cli-adapter-source"], commandScopeBuiltInPackageCatalog)
	assertScopeClass(t, commands["typescript-public-api-surfaces"], commandScopeExplicitFileSystemScan)
	assertCommand(t, commands["adoption-contract-envelope"], "required", []string{"--agent-envelope", "--checked-scope", "--guidance-mode", "--input", "--materialization-manifest", "--mode", "--pilot", "--touched-rule-id"}, []string{"json"})
	assertCommand(t, commands["agent-route"], "required", []string{"--agent-envelope", "--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["capability-map-admission"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["conformance-profile"], "required", []string{"--format", "--input", "--input-pointer", "--list", "--profile", "--verify"}, []string{"json", "markdown"})
	assertCommand(t, commands["requirement-coverage-input-compose"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-coverage-view"], "required", []string{"--agent-envelope", "--format", "--input", "--input-pointer"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-proof-view"], "required", []string{"--empty-local-environment-policy", "--format", "--input", "--input-pointer", "--local-environment-class", "--scope"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-source-view"], "required", []string{"--format", "--input", "--input-pointer"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-spec-tree"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-spec-tree-view"], "required", []string{"--format", "--input", "--input-pointer", "--output"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-browser-server"], "required", []string{"--empty-local-environment-policy", "--host", "--input", "--input-pointer", "--local-environment-class", "--open", "--port", "--scope", "--serve", "--view"}, []string{"json", "server"})
	assertCommand(t, commands["test-evidence-inventory"], "required", []string{"--input", "--input-pointer", "--normalized-inventory", "--projection"}, []string{"json", "normalized-inventory"})
	assertCommand(t, commands["workspace-manifest-facts"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-impact-input-compose"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["registry-consumer-proof-input-compose"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-authoring-plan"], "required", []string{"--input", "--input-pointer"}, []string{"json"})

	expectedAgentEnvelopeCommands := commandsWithBool(commands, func(command cliContractCommand) bool {
		return command.AgentEnvelope != nil && *command.AgentEnvelope
	})
	assertStringSet(t, agentEnvelopeCommands, expectedAgentEnvelopeCommands, "agent envelope command helper list")
	for _, command := range expectedAgentEnvelopeCommands {
		if commands[command].AgentEnvelope == nil || !*commands[command].AgentEnvelope {
			t.Fatalf("%s must advertise agent envelope support", command)
		}
	}
	expectedContractEnvelopeCommands := commandsWithBool(commands, func(command cliContractCommand) bool {
		return command.ContractEnvelope != nil && *command.ContractEnvelope
	})
	assertStringSet(t, contractEnvelopeCommands, expectedContractEnvelopeCommands, "contract envelope command helper list")
	for _, command := range expectedContractEnvelopeCommands {
		if commands[command].ContractEnvelope == nil || !*commands[command].ContractEnvelope {
			t.Fatalf("%s must advertise contract envelope support", command)
		}
	}
}

func assertStringSet(t *testing.T, actual []string, expected []string, label string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("%s length=%d want %d; actual=%v expected=%v", label, len(actual), len(expected), actual, expected)
	}
	for index, value := range expected {
		if actual[index] != value {
			t.Fatalf("%s[%d]=%q want %q; actual=%v expected=%v", label, index, actual[index], value, actual, expected)
		}
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func commandsWithBool(commands map[string]cliContractCommand, predicate func(cliContractCommand) bool) []string {
	values := []string{}
	for name, command := range commands {
		if predicate(command) {
			values = append(values, name)
		}
	}
	sort.Strings(values)
	return values
}

func commandDescriptorContractParityProblems(descriptors []commandDescriptor, commands []cliContractCommand) []string {
	problems := []string{}
	descriptorByName := map[string]commandDescriptor{}
	for _, descriptor := range descriptors {
		if _, exists := descriptorByName[descriptor.name]; exists {
			problems = append(problems, "duplicate descriptor "+descriptor.name)
			continue
		}
		descriptorByName[descriptor.name] = descriptor
	}
	commandByName := map[string]cliContractCommand{}
	for _, command := range commands {
		if _, exists := commandByName[command.Command]; exists {
			problems = append(problems, "duplicate contract command "+command.Command)
			continue
		}
		commandByName[command.Command] = command
	}
	for name, descriptor := range descriptorByName {
		command, ok := commandByName[name]
		if !ok {
			problems = append(problems, "descriptor command missing contract "+name)
			continue
		}
		if string(descriptor.input) != command.Input {
			problems = append(problems, "input drift "+name)
		}
		if !equalStringSets(descriptor.allowedFlags, command.AllowedFlags) {
			problems = append(problems, "flag drift "+name)
		}
		if !equalStringSets(descriptor.outputModes, command.OutputModes) {
			problems = append(problems, "output mode drift "+name)
		}
		if string(descriptor.scopeClass) != command.ScopeClass {
			problems = append(problems, "scope class drift "+name)
		}
		if descriptor.agentEnvelope != (command.AgentEnvelope != nil && *command.AgentEnvelope) {
			problems = append(problems, "agent envelope drift "+name)
		}
		if descriptor.contractEnvelope != (command.ContractEnvelope != nil && *command.ContractEnvelope) {
			problems = append(problems, "contract envelope drift "+name)
		}
	}
	for name := range commandByName {
		if _, ok := descriptorByName[name]; !ok {
			problems = append(problems, "contract command missing descriptor "+name)
		}
	}
	sort.Strings(problems)
	return problems
}

func commandDescriptorTopologyProblems(descriptors []commandDescriptor) []string {
	problems := []string{}
	for _, descriptor := range descriptors {
		if !isKnownCommandRunner(descriptor.runner) {
			problems = append(problems, "unknown runner "+descriptor.name)
		}
		if !isKnownCommandScopeClass(descriptor.scopeClass) {
			problems = append(problems, "unknown scope class "+descriptor.name)
		}
		if descriptor.runner == commandRunnerPlanning && !isExplicitPlanningCommand(descriptor.name) {
			problems = append(problems, "planning command lacks explicit route "+descriptor.name)
		}
		if len(descriptor.semanticOwnerDirs) == 0 {
			problems = append(problems, "missing semantic owner dirs "+descriptor.name)
		}
		if !isSortedUnique(descriptor.allowedFlags) || !isSortedUnique(descriptor.outputModes) || !isSortedUnique(descriptor.semanticOwnerDirs) || !isSortedUnique(descriptor.semanticAppTests) {
			problems = append(problems, "unsorted descriptor list "+descriptor.name)
		}
		if descriptor.input == commandInputNone && descriptor.runner == commandRunnerGenericInput {
			problems = append(problems, "no-input command uses generic input runner "+descriptor.name)
		}
	}
	sort.Strings(problems)
	return problems
}

func cloneCommandDescriptors(descriptors []commandDescriptor) []commandDescriptor {
	clone := make([]commandDescriptor, 0, len(descriptors))
	for _, descriptor := range descriptors {
		clone = append(clone, descriptor.clone())
	}
	return clone
}

func cloneCLIContractCommands(commands []cliContractCommand) []cliContractCommand {
	clone := make([]cliContractCommand, 0, len(commands))
	for _, command := range commands {
		copied := command
		copied.AllowedFlags = cloneStrings(command.AllowedFlags)
		copied.OutputModes = cloneStrings(command.OutputModes)
		clone = append(clone, copied)
	}
	return clone
}

func mutateDescriptor(name string, mutate func(*commandDescriptor)) []commandDescriptor {
	descriptors := cloneCommandDescriptors(commandDescriptors)
	for index := range descriptors {
		if descriptors[index].name == name {
			mutate(&descriptors[index])
			return descriptors
		}
	}
	panic("unknown command descriptor in test: " + name)
}

func helpLineForCommand(help string, command string) string {
	prefix := "  agentic-proofkit " + command
	for _, line := range strings.Split(help, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func helpLineFlags(line string) []string {
	flags := []string{}
	seen := map[string]struct{}{}
	for _, field := range strings.Fields(line) {
		for _, part := range strings.Split(field, "|") {
			token := strings.Trim(part, "[](),")
			if strings.HasPrefix(token, "<") || token == "-" || token == "->" {
				continue
			}
			if strings.HasPrefix(token, "--") || (len(token) == 2 && strings.HasPrefix(token, "-")) {
				if _, exists := seen[token]; exists {
					continue
				}
				seen[token] = struct{}{}
				flags = append(flags, token)
			}
		}
	}
	sort.Strings(flags)
	return flags
}

func stringsAsAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func TestHelpCommandContractForms(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.012212946147973847974188673193955565304078130183905790171739464374424221304025")
	for _, args := range [][]string{{"help"}, {"help", "--help"}, {"help", "-h"}, {"--help"}, {"-h"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), args, strings.NewReader(""), &stdout, &stderr)
			if status != 0 || stderr.Len() != 0 {
				t.Fatalf("help failed status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "agentic-proofkit help") {
				t.Fatalf("help output missing help route: %s", stdout.String())
			}
		})
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"help", "--input", "-"}, strings.NewReader(""), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "help supports only") {
		t.Fatalf("unexpected invalid help result status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
}

func TestConformanceProfileContractRejectsHTMLMode(t *testing.T) {
	contract := readCLIContract(t)
	var profile *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "conformance-profile" {
			profile = &contract.Commands[index]
			break
		}
	}
	if profile == nil {
		t.Fatal("conformance-profile missing from CLI contract")
	}
	if contains(profile.OutputModes, "html") {
		t.Fatal("conformance-profile contract must not advertise html output")
	}
}

type cliContract struct {
	Commands        []cliContractCommand `json:"commands"`
	ContractID      string               `json:"contractId"`
	PackageName     string               `json:"packageName"`
	ProcessContract any                  `json:"processContract"`
	SchemaVersion   int                  `json:"schemaVersion"`
}

type cliContractCommand struct {
	AgentEnvelope    *bool    `json:"agentEnvelope,omitempty"`
	AllowedFlags     []string `json:"allowedFlags"`
	Command          string   `json:"command"`
	ContractEnvelope *bool    `json:"contractEnvelope,omitempty"`
	Input            string   `json:"input"`
	InputContract    any      `json:"inputContract,omitempty"`
	InputPointer     bool     `json:"inputPointer"`
	OutputContract   any      `json:"outputContract,omitempty"`
	OutputModes      []string `json:"outputModes"`
	ScopeClass       string   `json:"scopeClass"`
	Stdin            bool     `json:"stdin"`
}

func readCLIContract(t *testing.T) cliContract {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), "proofkit", "cli-contract.v1.json"))
	if err != nil {
		t.Fatalf("open CLI contract: %v", err)
	}
	defer file.Close()
	contract, err := admission.DecodeTypedJSON[cliContract](file, 16<<20)
	if err != nil {
		t.Fatalf("decode CLI contract: %v", err)
	}
	return contract
}

func assertCLIContractSchema(t *testing.T) {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), "proofkit", "cli-contract.v1.json"))
	if err != nil {
		t.Fatalf("open CLI contract: %v", err)
	}
	defer file.Close()
	record, err := admission.DecodeTypedJSON[map[string]json.RawMessage](file, 16<<20)
	if err != nil {
		t.Fatalf("decode raw CLI contract: %v", err)
	}
	assertKeys(t, "CLI contract", keys(record), []string{"commands", "contractId", "packageName", "processContract", "schemaVersion"})
	var processContract map[string]json.RawMessage
	if err := json.Unmarshal(record["processContract"], &processContract); err != nil {
		t.Fatalf("decode process contract: %v", err)
	}
	assertKeys(t, "CLI process contract", keys(processContract), []string{"failureExitCode", "stderr", "stdout", "successExitCode"})
	var successExitCode int
	if err := json.Unmarshal(processContract["successExitCode"], &successExitCode); err != nil || successExitCode != 0 {
		t.Fatalf("successExitCode=%d err=%v, want 0", successExitCode, err)
	}
	var failureExitCode int
	if err := json.Unmarshal(processContract["failureExitCode"], &failureExitCode); err != nil || failureExitCode != 1 {
		t.Fatalf("failureExitCode=%d err=%v, want 1", failureExitCode, err)
	}
	var commands []map[string]json.RawMessage
	if err := json.Unmarshal(record["commands"], &commands); err != nil {
		t.Fatalf("decode raw CLI commands: %v", err)
	}
	allowedCommandKeys := map[string]struct{}{
		"agentEnvelope":    {},
		"allowedFlags":     {},
		"command":          {},
		"contractEnvelope": {},
		"input":            {},
		"inputContract":    {},
		"inputPointer":     {},
		"outputContract":   {},
		"outputModes":      {},
		"scopeClass":       {},
		"stdin":            {},
	}
	for index, command := range commands {
		for key := range command {
			if _, ok := allowedCommandKeys[key]; !ok {
				t.Fatalf("CLI command %d has unsupported key %s", index, key)
			}
		}
		for _, required := range []string{"allowedFlags", "command", "input", "inputPointer", "outputModes", "scopeClass", "stdin"} {
			if _, ok := command[required]; !ok {
				t.Fatalf("CLI command %d missing required key %s", index, required)
			}
		}
	}
}

func TestRequirementProofSourceSetContractDescribesProjection(t *testing.T) {
	contract := readCLIContract(t)
	var sourceSet *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-proof-source-set" {
			sourceSet = &contract.Commands[index]
			break
		}
	}
	if sourceSet == nil {
		t.Fatal("requirement-proof-source-set missing from CLI contract")
	}
	if sourceSet.InputContract == nil {
		t.Fatal("requirement-proof-source-set must expose inputContract")
	}
	if sourceSet.OutputContract == nil {
		t.Fatal("requirement-proof-source-set must expose outputContract")
	}
	inputContract := canonicalJSONValue(t, sourceSet.InputContract).(map[string]any)
	optionalFields := inputContract["optionalFields"].(map[string]any)
	projection := optionalFields["projection"].(map[string]any)
	fields := projection["fields"].(map[string]any)
	kind := fields["kind"].(map[string]any)
	if !reflect.DeepEqual(kind["enum"], []any{"canonical_contract", "resolver_input"}) {
		t.Fatalf("projection.kind enum=%v, want canonical_contract/resolver_input", kind["enum"])
	}
	if _, ok := fields["selectedSourceIds"]; !ok {
		t.Fatal("projection.selectedSourceIds missing from source-set input contract")
	}
	outputContract := canonicalJSONValue(t, sourceSet.OutputContract).(map[string]any)
	variants := outputContract["variants"].([]any)
	if len(variants) != 2 {
		t.Fatalf("source-set output variants=%v, want 2", variants)
	}
	wantVariants := map[string]string{
		"proofkit.requirement-proof-source-set.canonical_contract": "contract",
		"proofkit.requirement-proof-source-set.resolver_input":     "resolverInput",
	}
	for _, raw := range variants {
		variant := raw.(map[string]any)
		kind, _ := variant["projectionKind"].(string)
		field, _ := variant["payloadField"].(string)
		if wantVariants[kind] != field {
			t.Fatalf("unexpected source-set output variant kind=%q field=%q", kind, field)
		}
		delete(wantVariants, kind)
	}
	if len(wantVariants) != 0 {
		t.Fatalf("source-set output variants missing: %v", wantVariants)
	}
}

func TestRequirementCoverageViewContractDescribesMachineClassifications(t *testing.T) {
	contract := readCLIContract(t)
	var coverage *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-coverage-view" {
			coverage = &contract.Commands[index]
			break
		}
	}
	if coverage == nil {
		t.Fatal("requirement-coverage-view missing from CLI contract")
	}
	if coverage.OutputContract == nil {
		t.Fatal("requirement-coverage-view must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, coverage.OutputContract).(map[string]any)
	classificationRecords := outputContract["classificationRecords"].(map[string]any)
	failure := classificationRecords["failureClassifications"].(map[string]any)
	warning := classificationRecords["warningClassifications"].(map[string]any)
	if failure["sourceField"] != "failures" || failure["severity"] != "failure" {
		t.Fatalf("failure classification contract drift: %#v", failure)
	}
	if warning["sourceField"] != "warnings" || warning["severity"] != "warning" {
		t.Fatalf("warning classification contract drift: %#v", warning)
	}
	ids := stringsFromAny(outputContract["classificationIds"].([]any))
	assertStringSet(t, ids, []string{
		"declared_dead_zone",
		"failed_test_inventory",
		"missing_requirement_binding",
		"missing_semantic_test",
		"nonsemantic_command_evidence",
		"nonsemantic_governance_evidence",
		"not_applicable_with_reason",
		"owner_scope_violation",
		"routing_smoke_only",
		"unknown_reference",
	}, "requirement coverage classification ids")
}

func TestTestEvidenceInventoryContractDescribesMachineClassifications(t *testing.T) {
	contract := readCLIContract(t)
	var inventory *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "test-evidence-inventory" {
			inventory = &contract.Commands[index]
			break
		}
	}
	if inventory == nil {
		t.Fatal("test-evidence-inventory missing from CLI contract")
	}
	if inventory.OutputContract == nil {
		t.Fatal("test-evidence-inventory must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, inventory.OutputContract).(map[string]any)
	classificationRecords := outputContract["classificationRecords"].(map[string]any)
	failure := classificationRecords["failureClassifications"].(map[string]any)
	warning := classificationRecords["warningClassifications"].(map[string]any)
	if failure["sourceDiagnosticKey"] != "failures" || failure["severity"] != "failure" {
		t.Fatalf("inventory failure classification contract drift: %#v", failure)
	}
	if warning["sourceDiagnosticKey"] != "warnings" || warning["severity"] != "warning" {
		t.Fatalf("inventory warning classification contract drift: %#v", warning)
	}
	qualityFindingFields := outputContract["qualityFindingFields"].(map[string]any)
	assertStringSet(t, sortedMapKeys(qualityFindingFields), []string{
		"class",
		"evidenceRefs",
		"findingId",
		"nonClaims",
		"ownerReviewState",
		"severity",
	}, "test evidence inventory quality finding fields")
	ids := stringsFromAny(outputContract["classificationIds"].([]any))
	assertStringSet(t, ids, []string{
		"candidate_only",
		"declared_duplicate_falsifier",
		"duplicate_falsifier_candidate",
		"empty_oracle",
		"fixture_leak_risk",
		"flaky_time",
		"implementation_mirror",
		"import_cost_leak",
		"invalid_falsifier_supersession",
		"missing_edge",
		"missing_executable_command_ref",
		"missing_semantic_anchor",
		"mock_tests_mock",
		"over_broad_integration",
		"routing_smoke_only",
		"selector_fragility",
		"snapshot_without_oracle",
		"tautology",
		"unasserted_diagnostic",
		"weak_or_empty_oracle",
		"wrong_boundary",
		"wrong_evidence_boundary",
	}, "test evidence inventory classification ids")
}

func TestRequirementCoverageInputComposeContractDescribesDirectViewInput(t *testing.T) {
	contract := readCLIContract(t)
	var compose *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-coverage-input-compose" {
			compose = &contract.Commands[index]
			break
		}
	}
	if compose == nil {
		t.Fatal("requirement-coverage-input-compose missing from CLI contract")
	}
	if compose.OutputContract == nil {
		t.Fatal("requirement-coverage-input-compose must expose outputContract")
	}
	if compose.InputContract == nil {
		t.Fatal("requirement-coverage-input-compose must expose inputContract")
	}
	inputContract := canonicalJSONValue(t, compose.InputContract).(map[string]any)
	modes := inputContract["modes"].(map[string]any)
	normalized := modes["normalized"].(map[string]any)
	assertStringSet(t, stringsFromAny(normalized["requires"].([]any)), []string{
		"compactProofContract",
		"normalizedTestEvidenceInventory",
	}, "requirement coverage input compose normalized required fields")
	assertStringSet(t, stringsFromAny(normalized["forbids"].([]any)), []string{
		"requirementProofBinding",
		"testEvidenceInventory",
	}, "requirement coverage input compose normalized forbidden fields")
	direct := modes["direct"].(map[string]any)
	assertStringSet(t, stringsFromAny(direct["requires"].([]any)), []string{
		"requirementProofBinding",
		"testEvidenceInventory",
	}, "requirement coverage input compose direct required fields")
	assertStringSet(t, stringsFromAny(direct["forbids"].([]any)), []string{
		"compactProofContract",
		"normalizedTestEvidenceInventory",
	}, "requirement coverage input compose direct forbidden fields")
	if direct["admittedInventoryAuthority"] != "caller_owned_inventory" {
		t.Fatalf("direct admittedInventoryAuthority=%#v want caller_owned_inventory", direct["admittedInventoryAuthority"])
	}
	assertStringSet(t, stringsFromAny(direct["rejects"].([]any)), []string{
		"caller_owned_inventory_source_set",
		"caller_owned_test_discovery_candidate_inventory",
	}, "requirement coverage input compose direct rejected authorities")
	outputContract := canonicalJSONValue(t, compose.OutputContract).(map[string]any)
	fields := stringsFromAny(outputContract["requiredFields"].([]any))
	assertStringSet(t, fields, []string{
		"compactProofContract",
		"coverageUniverse",
		"localEnvironmentPolicy",
		"options",
		"ownerInvariantRegistry",
		"requirementProofBinding",
		"requirementSource",
		"schemaVersion",
		"testEvidenceInventory",
		"viewInputId",
	}, "requirement coverage input compose required fields")
	optionalFields := stringsFromAny(outputContract["optionalFields"].([]any))
	assertStringSet(t, optionalFields, []string{
		"normalizedTestEvidenceInventory",
	}, "requirement coverage input compose optional fields")
	if outputContract["provenanceRule"] == "" {
		t.Fatalf("requirement coverage input compose output contract must describe normalized provenance")
	}
}

func TestWitnessPlanContractDescribesBindingProjectionInput(t *testing.T) {
	contract := readCLIContract(t)
	var witnessPlan *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "witness-plan" {
			witnessPlan = &contract.Commands[index]
			break
		}
	}
	if witnessPlan == nil {
		t.Fatal("witness-plan missing from CLI contract")
	}
	if witnessPlan.InputContract == nil {
		t.Fatal("witness-plan must expose inputContract")
	}
	inputContract := canonicalJSONValue(t, witnessPlan.InputContract).(map[string]any)
	variants := inputContract["variants"].(map[string]any)
	bindingProjection := variants["requirement-bindings"].(map[string]any)
	assertStringSet(t, stringsFromAny(bindingProjection["requires"].([]any)), []string{
		"projection",
		"requirementProofBinding",
		"schemaVersion",
		"vocabulary",
	}, "witness-plan requirement-bindings required fields")
	assertStringSet(t, stringsFromAny(bindingProjection["admissionRules"].([]any)), []string{
		"requirementProofBinding must pass requirement-bindings admission",
		"vocabulary must pass witness command vocabulary admission",
		"binding-derived projection requires exactly one admitted parallelGroup; multi-group vocabularies require an explicit witness command catalog",
		"display command text must be display-only command text without shell control tokens, quoting, escaping, or secret-like tokens",
		"each referenced environment class must admit networkPolicy none, credentialClass none, and cachePolicy disabled",
	}, "witness-plan requirement-bindings admission rules")
}

func TestRequirementImpactInputComposeContractDescribesDirectImpactInput(t *testing.T) {
	contract := readCLIContract(t)
	var compose *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-impact-input-compose" {
			compose = &contract.Commands[index]
			break
		}
	}
	if compose == nil {
		t.Fatal("requirement-impact-input-compose missing from CLI contract")
	}
	if compose.OutputContract == nil {
		t.Fatal("requirement-impact-input-compose must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, compose.OutputContract).(map[string]any)
	fields := stringsFromAny(outputContract["requiredFields"].([]any))
	assertStringSet(t, fields, []string{
		"baseCommit",
		"baseRef",
		"changedBindingRecordIds",
		"changedPaths",
		"changedRecordIds",
		"changedWitnessPathCoverage",
		"generatedArtifactRules",
		"headCommit",
		"headRef",
		"ignoredProofLikePaths",
		"nonClaims",
		"obligationCatalog",
		"preexistingFailures",
		"proofLikePaths",
		"schemaVersion",
	}, "requirement impact input compose required fields")
}

func TestWorkspaceManifestFactsContractDescribesFactProjection(t *testing.T) {
	contract := readCLIContract(t)
	var workspace *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "workspace-manifest-facts" {
			workspace = &contract.Commands[index]
			break
		}
	}
	if workspace == nil {
		t.Fatal("workspace-manifest-facts missing from CLI contract")
	}
	if workspace.OutputContract == nil {
		t.Fatal("workspace-manifest-facts must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, workspace.OutputContract).(map[string]any)
	fields := stringsFromAny(outputContract["requiredFields"].([]any))
	assertStringSet(t, fields, []string{
		"changedPackagePlanPackages",
		"diagnostics",
		"knownPackageNames",
		"manifestSources",
		"nonClaims",
		"packageUniverse",
		"packages",
		"projectionId",
		"reportId",
		"reportKind",
		"root",
		"schemaVersion",
		"shardPartitionPackages",
		"state",
		"summary",
	}, "workspace manifest facts required fields")
	records := outputContract["records"].(map[string]any)
	assertOutputRecordFields(t, records, "root", []string{"dependencyRefs", "name", "scripts"})
	assertOutputRecordFields(t, records, "package", []string{"dependencyRefs", "dirName", "name", "scripts"})
	assertOutputRecordFields(t, records, "script", []string{"command", "name"})
	assertOutputRecordFields(t, records, "dependencyRef", []string{"field", "name", "version"})
	assertOutputRecordFields(t, records, "rootManifestSource", []string{"manifestPath", "name", "packageDir"})
	assertOutputRecordFields(t, records, "packageManifestSource", []string{"dirName", "manifestPath", "name", "packageDir"})
	assertOutputRecordFields(t, records, "workspaceDependencyEdge", []string{"field", "fromKind", "fromName", "toName", "version"})
	assertOutputRecordFields(t, records, "changedPackagePlanPackage", []string{"dirName", "name", "workspaceDependencies"})
	assertOutputRecordFields(t, records, "shardPartitionPackage", []string{"name", "workspaceDependencies"})
}

func assertOutputRecordFields(t *testing.T, records map[string]any, recordName string, expected []string) {
	t.Helper()
	record, ok := records[recordName].(map[string]any)
	if !ok {
		t.Fatalf("output record %s missing", recordName)
	}
	fields := stringsFromAny(record["requiredFields"].([]any))
	assertStringSet(t, fields, expected, recordName+" required fields")
}

func TestAgentRouteInputContractMatchesAdmission(t *testing.T) {
	contract := readCLIContract(t)
	var route *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "agent-route" {
			route = &contract.Commands[index]
			break
		}
	}
	if route == nil {
		t.Fatal("agent-route missing from CLI contract")
	}
	if route.InputContract == nil {
		t.Fatal("agent-route must expose inputContract")
	}
	got := canonicalJSONValue(t, route.InputContract)
	want := canonicalJSONValue(t, agentroute.InputContract())
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("agent-route input contract drift\ngot:  %#v\nwant: %#v", got, want)
	}
}

func canonicalJSONValue(t *testing.T, value any) any {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("unmarshal value: %v", err)
	}
	return decoded
}

func stringsFromAny(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, _ := value.(string)
		result = append(result, text)
	}
	return result
}

func assertCommand(t *testing.T, command cliContractCommand, input string, flags []string, modes []string) {
	t.Helper()
	if command.Command == "" {
		t.Fatal("command missing from contract")
	}
	if command.Input != input {
		t.Fatalf("%s input=%s want %s", command.Command, command.Input, input)
	}
	if !equalStrings(command.AllowedFlags, flags) {
		t.Fatalf("%s flags=%v want %v", command.Command, command.AllowedFlags, flags)
	}
	if !equalStrings(command.OutputModes, modes) {
		t.Fatalf("%s modes=%v want %v", command.Command, command.OutputModes, modes)
	}
}

func assertScopeClass(t *testing.T, command cliContractCommand, scopeClass commandScopeClass) {
	t.Helper()
	if command.ScopeClass != string(scopeClass) {
		t.Fatalf("%s scopeClass=%s want %s", command.Command, command.ScopeClass, scopeClass)
	}
}

func assertSortedUnique(t *testing.T, values []string, context string) {
	t.Helper()
	for index := range values {
		if values[index] == "" {
			t.Fatalf("%s contains empty item", context)
		}
		if index > 0 && values[index-1] >= values[index] {
			t.Fatalf("%s must be sorted and unique: %v", context, values)
		}
	}
}

func assertKeys(t *testing.T, context string, got []string, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if !equalStrings(got, want) {
		t.Fatalf("%s keys=%v want %v", context, got, want)
	}
}

func keys(record map[string]json.RawMessage) []string {
	result := make([]string, 0, len(record))
	for key := range record {
		result = append(result, key)
	}
	return result
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStringSets(left []string, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return equalStrings(left, right)
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
