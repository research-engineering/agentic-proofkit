package app

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentintegration"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type integrationLifecycleArgs struct {
	tool, operation, root, format, color string
	expectedTransaction, expectedDesired string
	transaction, action                  string
}

func runAgentIntegrationLifecycle(ctx context.Context, command string, args []string, stdout, stderr io.Writer, presentation PresentationCapabilities) int {
	options, err := parseIntegrationLifecycleArgs(command, args)
	if err != nil {
		return writeJSON(nil, 1, err, stdout, stderr)
	}
	var value any
	var plain string
	var exitCode int
	if command == "integration-recover" {
		receipt, failure := agentintegration.RecoverLifecycle(ctx, options.root, options.transaction, options.action)
		value, plain, exitCode, err = receipt.JSONValue(), receipt.Text(), receipt.ExitCode(), failure
	} else {
		capabilities, failure := integrationCapabilities(commandDescriptorByName, generatedCommandContractMetadataByName)
		if failure != nil {
			return writeJSON(nil, 1, failure, stdout, stderr)
		}
		document, failure := agentintegration.Source(options.tool, capabilities)
		if failure != nil {
			return writeJSON(nil, 1, failure, stdout, stderr)
		}
		if command == "integration-plan" {
			plan, failure := agentintegration.PlanLifecycle(ctx, options.root, document, options.operation)
			value, plain, exitCode, err = plan.JSONValue(), plan.Text(), plan.ExitCode(), failure
		} else {
			receipt, failure := agentintegration.ApplyLifecycle(ctx, options.root, document, options.operation, options.expectedTransaction, options.expectedDesired)
			value, plain, exitCode, err = receipt.JSONValue(), receipt.Text(), receipt.ExitCode(), failure
		}
	}
	if err != nil || options.format == "json" {
		return writeJSON(value, exitCode, err, stdout, stderr)
	}
	text, err := renderTerminalText(labeledTerminalText(plain), options.color, presentation)
	return writeText(text, exitCode, err, stdout, stderr)
}

func parseIntegrationLifecycleArgs(command string, args []string) (integrationLifecycleArgs, error) {
	descriptor, exists := commandDescriptorByName[command]
	if !exists || descriptor.runner != commandRunnerAgentIntegrationLifecycle {
		return integrationLifecycleArgs{}, fmt.Errorf("unsupported integration lifecycle command")
	}
	values := map[string]string{"--format": "json", "--color": "never"}
	seen := map[string]bool{}
	for index := 0; index < len(args); index += 2 {
		flag := args[index]
		if !slices.Contains(descriptor.allowedFlags, flag) {
			return integrationLifecycleArgs{}, fmt.Errorf("unsupported integration lifecycle argument")
		}
		if seen[flag] || index+1 >= len(args) || args[index+1] == "" {
			return integrationLifecycleArgs{}, fmt.Errorf("integration lifecycle arguments require one non-empty value per flag")
		}
		value := args[index+1]
		if choices := descriptor.flagValueChoices[flag]; len(choices) > 0 && !slices.Contains(choices, value) {
			return integrationLifecycleArgs{}, fmt.Errorf("integration lifecycle flag value is unsupported")
		}
		if flag == "--expect-transaction" || flag == "--expect-desired-state" || flag == "--transaction" {
			if _, err := admit.SHA256Ref(value, "integration lifecycle identity"); err != nil {
				return integrationLifecycleArgs{}, err
			}
		}
		seen[flag], values[flag] = true, value
	}
	for _, flag := range descriptor.requiredFlags {
		if !seen[flag] {
			return integrationLifecycleArgs{}, fmt.Errorf("integration lifecycle requires %s", flag)
		}
	}
	if seen["--color"] && values["--format"] != "text" {
		return integrationLifecycleArgs{}, fmt.Errorf("--color is valid only with --format text")
	}
	return integrationLifecycleArgs{
		tool: values["--tool"], operation: values["--operation"], root: values["--repo-root"],
		format: values["--format"], color: values["--color"],
		expectedTransaction: values["--expect-transaction"], expectedDesired: values["--expect-desired-state"],
		transaction: values["--transaction"], action: values["--action"],
	}, nil
}
