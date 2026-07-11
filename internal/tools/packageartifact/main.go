package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	return runWith(root, commandRunner{})
}

type Runner interface {
	Run(root string, argv []string) (int, error)
}

type commandRunner struct{}

func (commandRunner) Run(root string, argv []string) (int, error) {
	command := exec.Command(argv[0], argv[1:]...)
	command.Dir = root
	command.Env = os.Environ()
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), err
		}
		return 1, err
	}
	return 0, nil
}

type orchestrationDependencies struct {
	environ         func() []string
	now             func() time.Time
	toolchainDigest func() (string, error)
}

func runWith(root string, runner Runner) error {
	return runWithDependencies(root, runner, orchestrationDependencies{
		environ:         os.Environ,
		now:             func() time.Time { return time.Now().UTC() },
		toolchainDigest: packageartifactrecord.ToolchainDigest,
	})
}

func runWithDependencies(root string, runner Runner, dependencies orchestrationDependencies) error {
	if err := packageartifactrecord.Invalidate(root); err != nil {
		return err
	}
	if err := packageartifactrecord.PrepareCandidateArtifactOutputs(root); err != nil {
		return err
	}
	sourceRevision, sourceDigest, err := packageartifactrecord.SourceSnapshot(root)
	if err != nil {
		return err
	}
	environmentDigest := packageartifactrecord.EnvironmentDigest(dependencies.environ())
	toolchainDigest, err := dependencies.toolchainDigest()
	if err != nil {
		return err
	}

	startedAt := dependencies.now().UTC()
	exitCode, runErr := runner.Run(root, packageartifactrecord.CanonicalExecutionArgv())
	finishedAt := dependencies.now().UTC()

	evidenceErr := error(nil)
	afterRevision, afterSourceDigest, err := packageartifactrecord.SourceSnapshot(root)
	if err != nil {
		evidenceErr = errors.Join(evidenceErr, err)
	} else if afterRevision != sourceRevision || afterSourceDigest != sourceDigest {
		evidenceErr = errors.Join(evidenceErr, fmt.Errorf("package artifact command changed its source snapshot"))
	}
	afterEnvironmentDigest := packageartifactrecord.EnvironmentDigest(dependencies.environ())
	if afterEnvironmentDigest != environmentDigest {
		evidenceErr = errors.Join(evidenceErr, fmt.Errorf("package artifact command changed its environment snapshot"))
	}
	afterToolchainDigest, err := dependencies.toolchainDigest()
	if err != nil {
		evidenceErr = errors.Join(evidenceErr, err)
	} else if afterToolchainDigest != toolchainDigest {
		evidenceErr = errors.Join(evidenceErr, fmt.Errorf("package artifact command changed its toolchain snapshot"))
	}
	artifactEvidence, err := packageartifactrecord.ArtifactEvidenceSnapshot(root)
	if err != nil {
		evidenceErr = errors.Join(evidenceErr, err)
	}
	if runErr == nil && exitCode != 0 {
		runErr = fmt.Errorf("package artifact command returned exit code %d without an execution error", exitCode)
	}
	status := "failed"
	if runErr == nil && evidenceErr == nil {
		status = "passed"
	}
	artifactDigest := artifactEvidence.SnapshotDigest
	record := packageartifactrecord.Record{
		Argv:                   packageartifactrecord.CanonicalCommandArgv(),
		ArtifactSnapshotDigest: artifactDigest,
		CommandID:              packageartifactrecord.CommandID,
		EnvironmentDigest:      environmentDigest,
		ExecutionArgv:          packageartifactrecord.CanonicalExecutionArgv(),
		ExitCode:               exitCode,
		FinishedAt:             finishedAt.Format(time.RFC3339Nano),
		SchemaVersion:          packageartifactrecord.SchemaVersion,
		SourceRevision:         sourceRevision,
		SourceSnapshotDigest:   sourceDigest,
		StartedAt:              startedAt.Format(time.RFC3339Nano),
		Status:                 status,
		ToolchainDigest:        toolchainDigest,
	}
	if err := packageartifactrecord.Write(root, record); err != nil {
		return errors.Join(runErr, evidenceErr, err)
	}
	return errors.Join(runErr, evidenceErr)
}
