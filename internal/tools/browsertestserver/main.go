package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

func main() {
	workspace, err := browserfixture.Workspace()
	if err != nil {
		fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := requirementbrowser.Serve(ctx, workspace, requirementbrowser.Options{Host: "127.0.0.1", Port: 0, PortSet: true, SessionMode: "browse", View: "workspace"}, os.Stdout); err != nil && err != context.Canceled {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
