package main

import (
	"context"
	"fmt"
	"os"

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
	os.Exit(app.RunWithRenderer(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, renderer))
}
