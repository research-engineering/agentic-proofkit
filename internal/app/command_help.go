package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func isCommandHelpRequest(args []string) bool {
	return len(args) == 2 && args[0] != "help" && (args[1] == "--help" || args[1] == "-h")
}

func hasCommandHelpFlag(args []string) bool {
	return slices.Contains(args, "--help") || slices.Contains(args, "-h")
}

func commandUsage(descriptor commandDescriptor) string {
	return commandUsageWithRenderer(descriptor, cliexec.PathRenderer())
}

func commandUsageWithRenderer(descriptor commandDescriptor, renderer cliexec.Renderer) string {
	lines := []string{
		"Usage:",
		"  " + commandUsageLine(descriptor),
		"",
		"Installed invocation:",
		"  " + installedCommandUsageLineWithRenderer(descriptor, renderer),
	}
	if descriptor.name == "help" {
		lines = append(lines, "", "Installed help routes:")
		for _, form := range generatedCommandFamilyCatalog().HelpForms {
			lines = append(lines, "  "+renderer.DisplayCommand()+" "+form)
		}
	}
	lines = append(lines,
		"",
		"Command:",
		"  "+descriptor.name,
		"",
		"Input:",
		"  "+commandInputHelp(descriptor),
		"",
		"Output modes:",
		"  "+strings.Join(descriptor.outputModes, ", "),
		"",
		"Scope class:",
		"  "+string(descriptor.scopeClass),
		"",
		"Allowed flags:",
	)
	for _, flag := range descriptor.allowedFlags {
		lines = append(lines, "  "+flag)
	}
	if descriptor.name == "stack-preset" {
		lines = append(lines, "", "Copyable preset commands:")
		for _, presetID := range descriptor.flagValueChoices["--preset"] {
			lines = append(lines, "  "+renderer.DisplayCommand("stack-preset", "--preset", presetID))
		}
	}
	if descriptor.name == "stack-preset" || descriptor.name == "requirement-source-admission" {
		lines = append(lines,
			"",
			"Continue with the installed README first-valid-input example:",
			"  Path: node_modules/@research-engineering/agentic-proofkit/README.md",
		)
	}
	if len(descriptor.exactlyOneOfFlagGroups) > 0 || len(descriptor.atMostOneOfFlagGroups) > 0 || len(descriptor.flagPresenceRequirements) > 0 || len(descriptor.flagValueRequirements) > 0 || len(descriptor.singleOccurrenceFlags) > 0 {
		lines = append(lines, "", "Flag constraints:")
		for _, group := range descriptor.exactlyOneOfFlagGroups {
			lines = append(lines, "  Exactly one of: "+strings.Join(group, ", "))
		}
		for _, group := range descriptor.atMostOneOfFlagGroups {
			lines = append(lines, "  At most one of: "+strings.Join(group, ", "))
		}
		for _, requirement := range descriptor.flagPresenceRequirements {
			required := cloneStrings(requirement.RequiredFlags)
			for _, value := range requirement.RequiredFlagValues {
				required = append(required, value.Flag+" "+value.Value)
			}
			lines = append(lines, fmt.Sprintf("  %s requires: %s", requirement.Flag, strings.Join(required, ", ")))
		}
		for _, requirement := range descriptor.flagValueRequirements {
			required := cloneStrings(requirement.RequiredFlags)
			for _, value := range requirement.RequiredFlagValues {
				required = append(required, value.Flag+" "+value.Value)
			}
			lines = append(lines, fmt.Sprintf("  %s %s requires: %s", requirement.Flag, requirement.Value, strings.Join(required, ", ")))
		}
		for _, flag := range descriptor.singleOccurrenceFlags {
			lines = append(lines, "  May be specified once: "+flag)
		}
	}
	if len(descriptor.inputSchemaSummary) > 0 {
		lines = append(lines, "", "Input schema summary:")
		for _, field := range descriptor.inputSchemaSummary {
			lines = append(lines, "  "+field)
		}
	}
	if descriptor.agentEnvelope || descriptor.contractEnvelope {
		lines = append(lines, "", "Derived projections:")
		if descriptor.agentEnvelope {
			lines = append(lines, "  --agent-envelope emits an agent-facing projection over admitted input.")
		}
		if descriptor.contractEnvelope {
			lines = append(lines, "  --contract-envelope admits the command's aggregate contract envelope when provided.")
		}
	}
	lines = append(lines, "", "Public contract:")
	lines = append(lines, "  CLI command routing, root JSON shapes, output modes, exit codes, and flags are owned by proofkit/cli-contract.v2.json.")
	lines = append(lines, "  Nested field semantics remain owned by native command admission.")
	return strings.Join(lines, "\n") + "\n"
}

func installedCommandUsageLine(descriptor commandDescriptor) string {
	return installedCommandUsageLineWithRenderer(descriptor, cliexec.PathRenderer())
}

func installedCommandUsageLineWithRenderer(descriptor commandDescriptor, renderer cliexec.Renderer) string {
	return renderer.DisplayCommand() + strings.TrimPrefix(commandUsageLine(descriptor), cliexec.BinaryName)
}

func commandUsageLine(descriptor commandDescriptor) string {
	if descriptor.name == "help" {
		return "agentic-proofkit help [<command>|-h|--help]"
	}
	segments := []string{"agentic-proofkit", descriptor.name}
	if descriptor.input == commandInputRequired {
		segments = append(segments, "--input <path|->")
	}
	for _, flag := range descriptor.allowedFlags {
		if flagInExactlyOneGroup(descriptor.exactlyOneOfFlagGroups, flag) {
			continue
		}
		required := slices.Contains(descriptor.requiredFlags, flag)
		if choices := descriptor.flagValueChoices[flag]; len(choices) > 0 {
			segments = append(segments, optionalUsageSegment(flag+" <"+strings.Join(choices, "|")+">", required))
			continue
		}
		switch flag {
		case "--input":
			continue
		case "--input-pointer":
			segments = append(segments, "[--input-pointer <pointer>]")
		case "--format":
			segments = append(segments, "[--format <mode>]")
		case "--repo-root":
			segments = append(segments, optionalUsageSegment(flag+" <path>", required))
		case "--host":
			segments = append(segments, "[--host 127.0.0.1|::1]")
		case "--port":
			segments = append(segments, "[--port <port>]")
		case "--session-mode":
			segments = append(segments, "[--session-mode browse|one-shot-question]")
		case "--session-timeout-seconds":
			segments = append(segments, "[--session-timeout-seconds <1..7200>]")
		case "--scope":
			segments = append(segments, "[--scope <scope>]")
		case "--local-environment-class":
			segments = append(segments, "[--local-environment-class <id>]")
		case "--checked-scope":
			segments = append(segments, "[--checked-scope <scope>]")
		case "--guidance-mode", "--mode":
			segments = append(segments, optionalUsageSegment(fmt.Sprintf("%s <mode>", flag), required))
		case "--pilot", "--profile", "--preset", "--projection", "--view", "--language":
			segments = append(segments, optionalUsageSegment(fmt.Sprintf("%s <value>", flag), required))
		case "--touched-rule-id":
			segments = append(segments, "[--touched-rule-id <id>]")
		case "--agent-envelope", "--contract-envelope", "--empty-local-environment-policy", "--help", "-h", "--list", "--materialization-manifest", "--normalized-inventory", "--open", "--serve", "--stack-diverse", "--verify":
			segments = append(segments, "["+flag+"]")
		case "--output":
			segments = append(segments, "[--output <path>]")
		default:
			segments = append(segments, "["+flag+"]")
		}
	}
	for _, group := range descriptor.exactlyOneOfFlagGroups {
		alternatives := make([]string, 0, len(group))
		for _, flag := range group {
			alternatives = append(alternatives, usageFlagValue(flag))
		}
		segments = append(segments, "("+strings.Join(alternatives, " | ")+")")
	}
	return strings.Join(segments, " ")
}

func flagInExactlyOneGroup(groups [][]string, flag string) bool {
	for _, group := range groups {
		if slices.Contains(group, flag) {
			return true
		}
	}
	return false
}

func usageFlagValue(flag string) string {
	switch flag {
	case "--local-environment-class":
		return flag + " <id>"
	case "--profile":
		return flag + " <value>"
	default:
		return flag
	}
}

func optionalUsageSegment(value string, required bool) string {
	if required {
		return value
	}
	return "[" + value + "]"
}

func commandInputHelp(descriptor commandDescriptor) string {
	if descriptor.input == commandInputRequired {
		return "Requires explicit caller-owned JSON input through --input <path|->; stdin is only read when --input - is selected."
	}
	return "Does not accept caller JSON input and never reads stdin."
}

func parseInitArgs(args []string) (string, error) {
	preset := ""
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--preset":
			if index+1 >= len(args) {
				return "", fmt.Errorf("init --preset requires all, fresh, code-baseline, code-audit, legacy, or change-set")
			}
			preset = args[index+1]
			index++
		default:
			return "", fmt.Errorf("unsupported argument for init: %s", args[index])
		}
	}
	return preset, nil
}
