package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func main() {
	renderer, err := cliexec.AdmitLauncherProfile(
		os.Getenv(cliexec.LauncherProfileEnvironment),
		os.Getenv(cliexec.PythonExecutableEnvironment),
	)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, noColorPresent := os.LookupEnv("NO_COLOR")
	capabilities := app.PresentationCapabilities{
		StdoutIsTTY:    isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()),
		NoColorPresent: noColorPresent,
	}
	os.Exit(app.RunWithRendererAndCapabilities(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, renderer, capabilities))
}
