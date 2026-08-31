package main

import (
	"context"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
)

func main() {
	renderer, err := cliexec.AdmitLauncherProfile(
		os.Getenv(cliexec.LauncherProfileEnvironment),
		os.Getenv(cliexec.PythonExecutableEnvironment),
	)
	if err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
	_, noColorPresent := os.LookupEnv("NO_COLOR")
	capabilities := app.PresentationCapabilities{
		StdoutIsTTY:    isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()),
		NoColorPresent: noColorPresent,
	}
	os.Exit(app.RunWithRendererAndCapabilities(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, renderer, capabilities))
}
