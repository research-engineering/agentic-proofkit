package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

func main() {
	build := browserfixture.Workspace
	if len(os.Args) == 2 && os.Args[1] == "--lookup" {
		build = browserfixture.LookupWorkspace
	} else if len(os.Args) == 2 && os.Args[1] == "--paging" {
		build = browserfixture.PagingWorkspace
	} else if len(os.Args) == 2 && os.Args[1] == "--capacity" {
		build = browserfixture.CapacityWorkspace
	} else if len(os.Args) == 2 && os.Args[1] == "--graph-capacity" {
		build = browserfixture.GraphCapacityWorkspace
	} else if len(os.Args) == 2 && os.Args[1] == "--graph-numeric" {
		build = browserfixture.GraphNumericWorkspace
	} else if len(os.Args) == 2 && os.Args[1] == "--coverage-compact" {
		build = func() (map[string]any, error) { return browserfixture.CoverageWorkspace("compact", false) }
	} else if len(os.Args) == 2 && os.Args[1] == "--coverage-structured" {
		build = func() (map[string]any, error) { return browserfixture.CoverageWorkspace("structured", false) }
	} else if len(os.Args) == 2 && os.Args[1] == "--coverage-empty" {
		build = func() (map[string]any, error) { return browserfixture.CoverageWorkspace("compact", true) }
	} else if len(os.Args) != 1 {
		fatal(errors.New("unsupported browser fixture selector"))
	}
	workspace, err := build()
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
	diagnostic.WriteError(os.Stderr, err)
	os.Exit(1)
}
