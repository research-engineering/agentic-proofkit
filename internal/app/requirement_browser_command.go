package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func runRequirementBrowserServer(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseRequirementBrowserArgs(args)
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
	browserOptions := requirementbrowser.Options{
		EmptyLocalEnvironmentPolicy: options.emptyLocalEnvironmentPolicy,
		Host:                        options.host,
		LocalEnvironmentClasses:     options.localEnvironmentClasses,
		Open:                        options.open,
		Port:                        options.port,
		PortSet:                     options.portSet,
		ProofViewScope:              options.scope,
		View:                        options.view,
	}
	if options.serve {
		signalContext, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := requirementbrowser.Serve(signalContext, input, browserOptions, stdout); err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		return 0
	}
	output, exitCode, err := requirementbrowser.BuildPlan(input, browserOptions)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func parseRequirementBrowserArgs(args []string) (requirementBrowserArgs, error) {
	options := requirementBrowserArgs{host: "127.0.0.1", port: 4177}
	inputPointerSeen := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return requirementBrowserArgs{}, fmt.Errorf("--input requires a path")
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointerSeen || index+1 >= len(args) {
				return requirementBrowserArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointerSeen = true
			options.inputPointer = args[index+1]
			index++
		case "--view":
			if index+1 >= len(args) || (args[index+1] != "source" && args[index+1] != "proof" && args[index+1] != "coverage" && args[index+1] != "spec-tree") {
				return requirementBrowserArgs{}, fmt.Errorf("--view requires source, proof, coverage, or spec-tree")
			}
			options.view = args[index+1]
			index++
		case "--host":
			if index+1 >= len(args) || (args[index+1] != "127.0.0.1" && args[index+1] != "::1") {
				return requirementBrowserArgs{}, fmt.Errorf("--host requires loopback literal: 127.0.0.1 or ::1")
			}
			options.host = args[index+1]
			index++
		case "--port":
			if index+1 >= len(args) {
				return requirementBrowserArgs{}, fmt.Errorf("--port requires an integer from 0 to 65535")
			}
			port, err := strconv.Atoi(args[index+1])
			if err != nil || port < 0 || port > 65535 {
				return requirementBrowserArgs{}, fmt.Errorf("--port requires an integer from 0 to 65535")
			}
			options.port = port
			options.portSet = true
			index++
		case "--open":
			options.open = true
		case "--serve":
			options.serve = true
		case "--scope":
			if index+1 >= len(args) || (args[index+1] != "graph" && args[index+1] != "slice") {
				return requirementBrowserArgs{}, fmt.Errorf("--scope requires graph or slice")
			}
			options.scope = args[index+1]
			index++
		case "--local-environment-class":
			if index+1 >= len(args) || args[index+1] == "" {
				return requirementBrowserArgs{}, fmt.Errorf("--local-environment-class requires an id")
			}
			options.localEnvironmentClasses = append(options.localEnvironmentClasses, args[index+1])
			index++
		case "--empty-local-environment-policy":
			options.emptyLocalEnvironmentPolicy = true
		default:
			return requirementBrowserArgs{}, fmt.Errorf("unsupported argument: %s", args[index])
		}
	}
	if options.view == "" {
		return requirementBrowserArgs{}, fmt.Errorf("requirement-browser-server requires --view source, proof, coverage, or spec-tree")
	}
	if options.inputPath == "" {
		return requirementBrowserArgs{}, fmt.Errorf("--input is required")
	}
	if options.open && !options.serve {
		return requirementBrowserArgs{}, fmt.Errorf("--open requires --serve for requirement-browser-server")
	}
	if options.view != "proof" && options.scope != "" {
		return requirementBrowserArgs{}, fmt.Errorf("--scope is valid only for requirement-proof-view or proof requirement-browser-server")
	}
	if options.view != "proof" && (len(options.localEnvironmentClasses) > 0 || options.emptyLocalEnvironmentPolicy) {
		return requirementBrowserArgs{}, fmt.Errorf("--local-environment-class and --empty-local-environment-policy are valid only for requirement-proof-resolver, compact requirement-proof-view, or proof requirement-browser-server")
	}
	if len(options.localEnvironmentClasses) > 0 && options.emptyLocalEnvironmentPolicy {
		return requirementBrowserArgs{}, fmt.Errorf("--local-environment-class and --empty-local-environment-policy are mutually exclusive")
	}
	return options, nil
}
