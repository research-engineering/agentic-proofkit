package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func runAgentIntegration(ctx context.Context, command string, args []string, stdout, stderr io.Writer) int {
	options, err := parseAgentIntegrationArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	capabilities, err := integrationCapabilities(commandDescriptorByName, generatedCommandContractMetadataByName)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	document, err := agentintegration.Source(options.tool, capabilities)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	var output any = document.JSONValue()
	text, exitCode := document.Content(), 0
	if command == "integration-check" {
		result, err := agentintegration.Check(ctx, options.repositoryRoot, document)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		output, text = result.JSONValue(), result.Text()
		if result.State() != "current" {
			exitCode = 2
		}
	}
	if err := ctx.Err(); err != nil {
		writeDiagnosticf(stderr, "integration command cancelled before output")
		return 1
	}
	if options.format == "text" {
		return writeText(text, exitCode, nil, stdout, stderr)
	}
	return writeJSON(output, exitCode, nil, stdout, stderr)
}

type agentIntegrationArgs struct{ tool, format, repositoryRoot string }

func parseAgentIntegrationArgs(command string, args []string) (agentIntegrationArgs, error) {
	options := agentIntegrationArgs{format: "json"}
	if command != "integration-source" && command != "integration-check" {
		return options, fmt.Errorf("unsupported integration operation")
	}
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		flag := args[index]
		if flag != "--tool" && flag != "--format" && (flag != "--repo-root" || command != "integration-check") {
			return options, fmt.Errorf("unsupported integration argument")
		}
		if seen[flag] || index+1 >= len(args) || args[index+1] == "" {
			return options, fmt.Errorf("integration arguments require one non-empty value per flag")
		}
		seen[flag] = true
		index++
		switch flag {
		case "--tool":
			options.tool = args[index]
		case "--format":
			options.format = args[index]
		case "--repo-root":
			options.repositoryRoot = args[index]
		}
	}
	if !slices.Contains(agentintegration.Tools(), options.tool) {
		return options, fmt.Errorf("--tool requires claude or codex")
	}
	if options.format != "json" && options.format != "text" {
		return options, fmt.Errorf("--format requires json or text")
	}
	if command == "integration-check" && options.repositoryRoot == "" {
		return options, fmt.Errorf("integration check requires --repo-root")
	}
	return options, nil
}

func integrationCapabilities(descriptors map[string]commandDescriptor, metadata map[string]generatedCommandContractMetadata) ([]agentintegration.Capability, error) {
	commands := agentintegration.ConsumedCommands()
	result := make([]agentintegration.Capability, len(commands))
	for index, command := range commands {
		descriptor, exists := descriptors[command]
		contract, hasContract := metadata[command]
		if !exists || !hasContract {
			return nil, fmt.Errorf("integration consumed command contract is unavailable")
		}
		// This projection binds existing invocation owners. It is not a second
		// schema or a digest of every transitive implementation dependency.
		value := map[string]any{
			"command": command, "route": descriptor.routeTokens, "input": descriptor.input,
			"allowedFlags": descriptor.allowedFlags, "requiredFlags": descriptor.requiredFlags,
			"exactlyOneOfFlags": descriptor.exactlyOneOfFlagGroups, "atMostOneOfFlags": descriptor.atMostOneOfFlagGroups,
			"flagPresenceRequirements": descriptor.flagPresenceRequirements, "flagValueRequirements": descriptor.flagValueRequirements,
			"singleOccurrenceFlags": descriptor.singleOccurrenceFlags, "flagChoices": descriptor.flagValueChoices,
			"outputModes": descriptor.outputModes, "scopeClass": descriptor.scopeClass,
			"agentEnvelope": descriptor.agentEnvelope, "contractEnvelope": descriptor.contractEnvelope,
			"inputContractDigest": contract.InputContractSHA256, "outputContractDigest": contract.OutputContractSHA256,
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode integration invocation contract")
		}
		canonical, err := admission.DecodeJSON(bytes.NewReader(encoded), 64<<10)
		if err != nil {
			return nil, fmt.Errorf("admit integration invocation contract")
		}
		identity, err := digest.StableJSONSHA256Ref(canonical)
		if err != nil {
			return nil, err
		}
		result[index] = agentintegration.Capability{Command: command, Route: cloneStrings(descriptor.routeTokens), ContractDigest: identity}
	}
	return result, nil
}
