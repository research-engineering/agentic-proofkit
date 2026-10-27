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
	view := "workspace"
	var localEnvironmentClasses []string
	if len(os.Args) == 2 && os.Args[1] == "--readme-project" {
		serveReadmeProject()
		return
	}
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
	} else if len(os.Args) == 2 && os.Args[1] == "--graph-layout" {
		build = func() (map[string]any, error) { return browserfixture.GraphLayoutWorkspace(false) }
	} else if len(os.Args) == 2 && os.Args[1] == "--graph-layout-mixed" {
		build = func() (map[string]any, error) { return browserfixture.GraphLayoutWorkspace(true) }
	} else if len(os.Args) == 2 && os.Args[1] == "--coverage-compact" {
		build = func() (map[string]any, error) { return browserfixture.CoverageWorkspace("compact", false) }
	} else if len(os.Args) == 2 && os.Args[1] == "--coverage-structured" {
		build = func() (map[string]any, error) { return browserfixture.CoverageWorkspace("structured", false) }
	} else if len(os.Args) == 2 && os.Args[1] == "--coverage-empty" {
		build = func() (map[string]any, error) { return browserfixture.CoverageWorkspace("compact", true) }
	} else if len(os.Args) == 2 && os.Args[1] == "--source" {
		build = browserfixture.Source
		view = "source"
	} else if len(os.Args) == 2 && os.Args[1] == "--shared-source" {
		build = browserfixture.SharedScenarioSource
		view = "source"
	} else if len(os.Args) == 2 && os.Args[1] == "--static-source" {
		build = browserfixture.StaticSource
		view = "source"
	} else if len(os.Args) == 2 && os.Args[1] == "--static-tree" {
		build = browserfixture.StaticTree
		view = "spec-tree"
	} else if len(os.Args) == 2 && os.Args[1] == "--static-proof" {
		build = browserfixture.StaticProof
		view = "proof"
	} else if len(os.Args) == 2 && os.Args[1] == "--static-proof-compact" {
		build = browserfixture.StaticCompactProof
		view = "proof"
		localEnvironmentClasses = []string{"local-go"}
	} else if len(os.Args) == 2 && os.Args[1] == "--static-coverage" {
		build = func() (map[string]any, error) { return browserfixture.CoverageInput("structured") }
		view = "coverage"
	} else if len(os.Args) == 2 && os.Args[1] == "--static-coverage-gap" {
		build = browserfixture.CoverageGapInput
		view = "coverage"
	} else if len(os.Args) != 1 {
		fatal(errors.New("unsupported browser fixture selector"))
	}
	workspace, err := build()
	if err != nil {
		fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := requirementbrowser.Serve(ctx, workspace, requirementbrowser.Options{Host: "127.0.0.1", Port: 0, PortSet: true, SessionMode: "browse", View: view, LocalEnvironmentClasses: localEnvironmentClasses}, os.Stdout); err != nil && err != context.Canceled {
		fatal(err)
	}
}

// serveReadmeProject materializes the committed README project and serves it
// through the same project inspection path as the view command. The temporary
// project directory is removed on every exit path before a failure exits.
func serveReadmeProject() {
	directory, err := os.MkdirTemp("", "proofkit-readme-project-")
	if err != nil {
		fatal(err)
	}
	err = serveMaterializedReadmeProject(directory)
	if removeErr := os.RemoveAll(directory); err == nil {
		err = removeErr
	}
	if err != nil {
		fatal(err)
	}
}

func serveMaterializedReadmeProject(directory string) error {
	if err := browserfixture.MaterializeReadmeProject(directory); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := requirementbrowser.ServeProject(ctx, directory, requirementbrowser.Options{Host: "127.0.0.1", Port: 0, PortSet: true, SessionMode: "browse"}, os.Stdout); err != nil && err != context.Canceled {
		return err
	}
	return nil
}

func fatal(err error) {
	diagnostic.WriteError(os.Stderr, err)
	os.Exit(1)
}
