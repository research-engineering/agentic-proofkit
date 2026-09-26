package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func minimumCommand(ctx context.Context, directory string, environment []string, executable string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, err := workflowsmoke.RunProcessWithOutputLimits(bounded, workflowsmoke.ProcessCarrier{
		Directory: directory, Environment: environment, Executable: executable,
	}, workflowsmoke.Invocation{Args: args, StdinClass: workflowsmoke.StdinBytes}, workflowsmoke.ProcessOutputLimits{MaximumStdoutBytes: 2 << 20, MaximumStderrBytes: 64 << 10})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		// Host tools may mention ambient configuration in diagnostics. Do not
		// promote their arbitrary output into the public receipt or an error.
		return nil, fmt.Errorf("minimum smoke %s process exited with code %d", executable, result.ExitCode)
	}
	return result.Stdout, nil
}

func minimumDockerArgs(input, name, architecture, image string) []string {
	return []string{"run", "--rm", "--name", name, "--pull", "never", "--platform", "linux/" + architecture,
		"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "65534:65534", "--cpus", "1", "--memory", "256m", "--pids-limit", "64",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=256m,mode=1777", "--workdir", "/input",
		"--mount", "type=bind,src=" + input + ",dst=/input,readonly", image, "/input/runner", "verify-minimum-installed"}
}

type minimumDockerCommand func(context.Context, ...string) ([]byte, error)

func minimumDockerSmoke(ctx context.Context, input, architecture, image string) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "proofkit-python-minimum-" + hex.EncodeToString(nonce[:])
	command := func(ctx context.Context, args ...string) ([]byte, error) {
		return minimumCommand(ctx, "", nil, "docker", args...)
	}
	return minimumDockerLifecycle(ctx, command, input, name, architecture, image)
}

func minimumDockerLifecycle(ctx context.Context, command minimumDockerCommand, input, name, architecture, image string) (err error) {
	// Inspection failure is only a reason to try a pinned pull, never evidence
	// of absence or exclusive ownership. Images remain shared Docker cache.
	_, inspectErr := command(ctx, "image", "inspect", image, "--format", "{{.Os}}/{{.Architecture}}")
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, minimumDockerCleanup(cleanupContext, command, name), ctx.Err())
	}()
	if inspectErr != nil {
		if _, err := command(ctx, "pull", "--platform", "linux/"+architecture, image); err != nil {
			return err
		}
	}
	identity, err := command(ctx, "image", "inspect", image, "--format", "{{.Os}}/{{.Architecture}}")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(identity)) != "linux/"+architecture {
		return fmt.Errorf("minimum image architecture differs from native Docker architecture")
	}
	snapshotBytes, err := artifactfile.ReadBounded(input, "snapshot.json", 1<<20)
	if err != nil {
		return err
	}
	output, err := command(ctx, minimumDockerArgs(input, name, architecture, image)...)
	if err != nil {
		return err
	}
	expected := minimumInstalledResult(minimumHash(snapshotBytes), architecture)
	if !bytes.Equal(output, expected) {
		return fmt.Errorf("minimum installed smoke did not return the exact completed snapshot result")
	}
	return nil
}

func minimumDockerCleanup(ctx context.Context, command minimumDockerCommand, name string) error {
	filter := "name=^/" + name + "$"
	remaining, err := command(ctx, "ps", "-aq", "--filter", filter)
	if err != nil {
		return fmt.Errorf("minimum container cleanup status is unverified: %w", err)
	}
	if strings.TrimSpace(string(remaining)) != "" {
		if _, err := command(ctx, "rm", "-f", name); err != nil {
			return fmt.Errorf("minimum container cleanup failed: %w", err)
		}
	}
	remaining, err = command(ctx, "ps", "-aq", "--filter", filter)
	if err != nil || strings.TrimSpace(string(remaining)) != "" {
		return fmt.Errorf("minimum container cleanup could not confirm absence")
	}
	return nil
}
