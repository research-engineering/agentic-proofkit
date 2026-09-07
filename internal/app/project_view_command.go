package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
)

type projectViewArgs struct {
	repositoryRoot string
	serve          bool
	browser        requirementbrowser.Options
}

type projectViewRunner func(context.Context, descriptorArguments, io.Writer, io.Writer) int

type projectViewOperations struct {
	plan  func(context.Context, string, requirementbrowser.Options) (map[string]any, int, error)
	serve func(context.Context, string, requirementbrowser.Options, io.Writer) error
}

func runProjectView(ctx context.Context, parsed descriptorArguments, stdout, stderr io.Writer) int {
	return runProjectViewWithOperations(ctx, parsed, stdout, stderr, projectViewOperations{
		plan: requirementbrowser.BuildProjectPlan, serve: requirementbrowser.ServeProject,
	})
}

func runProjectViewWithOperations(ctx context.Context, parsed descriptorArguments, stdout, stderr io.Writer, operations projectViewOperations) int {
	options, err := parseProjectViewArgs(parsed)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if !options.serve {
		output, code, err := operations.plan(ctx, options.repositoryRoot, options.browser)
		return writeJSON(output, code, err, stdout, stderr)
	}
	signalContext, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := operations.serve(signalContext, options.repositoryRoot, options.browser, stdout); err != nil {
		if !errors.Is(err, requirementbrowser.ErrOneShotTerminal) {
			writeDiagnosticf(stderr, "view could not complete the browser session; use next with the same --repo-root")
		}
		return 1
	}
	return 0
}

// The dispatcher owns token classification and descriptor constraints. Values
// are consumed from that result; a path such as --serve is not reparsed here.
func parseProjectViewArgs(parsed descriptorArguments) (projectViewArgs, error) {
	if parsed.unexpected {
		return projectViewArgs{}, fmt.Errorf("unsupported argument for view")
	}
	options := projectViewArgs{
		serve: parsed.present["--serve"],
		browser: requirementbrowser.Options{
			Host: "127.0.0.1", View: "workspace", SessionMode: "browse",
			Open: parsed.present["--open"],
		},
	}
	for _, flag := range []string{"--repo-root", "--host", "--port", "--session-mode", "--session-timeout-seconds"} {
		if !parsed.present[flag] {
			continue
		}
		values := parsed.values[flag]
		if len(values) != 1 || values[0] == "" {
			return projectViewArgs{}, fmt.Errorf("%s requires a value", flag)
		}
		value := values[0]
		switch flag {
		case "--repo-root":
			options.repositoryRoot = value
		case "--host":
			options.browser.Host = value
		case "--session-mode":
			options.browser.SessionMode = value
		case "--port", "--session-timeout-seconds":
			number, err := parseBrowserInteger(flag, value)
			if err != nil {
				return projectViewArgs{}, err
			}
			if flag == "--port" {
				options.browser.Port, options.browser.PortSet = number, true
			} else {
				options.browser.SessionTimeout = time.Duration(number) * time.Second
			}
		}
	}
	return options, nil
}
