package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGeneratorFlagDiagnosticsPreserveProcessContract(t *testing.T) {
	root := sourceHygieneRepoRoot(t)
	secret := strings.Join([]string{"api", "_key=", "synthetic-generator-fixture"}, "")
	protectedFlag := strings.Join([]string{"gh", "p_", strings.Repeat("x", 36)}, "")
	for _, tool := range []string{"commandcontractgen", "commandfamilygen"} {
		t.Run(tool, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), tool)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./internal/tools/"+tool)
			build.Dir = root
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build failed: %v\n%s", err, output)
			}
			for _, test := range []struct {
				name   string
				args   []string
				exit   int
				marker string
			}{
				{"help-long", []string{"--help"}, 0, "Usage of " + tool + ":\n"},
				{"help-short", []string{"-h"}, 0, "Usage of " + tool + ":\n"},
				{"invalid-boolean", []string{"--check=not-a-boolean"}, 2, "invalid boolean value"},
				{"unknown-flag", []string{"--unknown"}, 2, "flag provided but not defined"},
				{"positional", []string{"unexpected"}, 1, tool + " accepts"},
				{"protected-boolean", []string{"--check=" + secret}, 2, "<redacted-diagnostic-value>"},
				{"protected-flag-name", []string{"--" + protectedFlag}, 2, "<redacted-diagnostic-value>"},
				{"protected-positional", []string{secret}, 1, tool + " accepts"},
			} {
				t.Run(test.name, func(t *testing.T) {
					directory := t.TempDir()
					command := exec.CommandContext(ctx, binary, test.args...)
					command.Dir = directory
					var stdout, stderr bytes.Buffer
					command.Stdout, command.Stderr = &stdout, &stderr
					err := command.Run()
					var exitErr *exec.ExitError
					if err != nil && !errors.As(err, &exitErr) {
						t.Fatalf("process did not complete: %v", err)
					}
					if code := command.ProcessState.ExitCode(); code != test.exit {
						t.Fatalf("exit=%d, want %d", code, test.exit)
					}
					if strings.Contains(stderr.String(), "synthetic-generator-fixture") || strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), protectedFlag) {
						t.Fatal("protected caller text escaped the diagnostic boundary")
					}
					if stdout.Len() != 0 || !strings.Contains(stderr.String(), test.marker) {
						t.Fatal("stdout/stderr contract mismatch")
					}
					entries, err := os.ReadDir(directory)
					if err != nil || len(entries) != 0 {
						t.Fatal("early exit unexpectedly wrote into the working directory")
					}
				})
			}
			t.Run("caller-argv-zero-is-not-usage-authority", func(t *testing.T) {
				command := exec.CommandContext(ctx, binary, "--help")
				command.Args[0] = "caller\n\t" + secret
				command.Dir = t.TempDir()
				output, err := command.CombinedOutput()
				if err != nil || !bytes.HasPrefix(output, []byte("Usage of "+tool+":\n")) || bytes.Contains(output, []byte("caller")) || bytes.Contains(output, []byte("synthetic-generator-fixture")) {
					t.Fatal("caller argv[0] affected command-owned usage")
				}
			})
			t.Run("check-current-projection", func(t *testing.T) {
				paths := []string{"internal/app/command_contract_generated.go", "internal/app/command_family_catalog_generated.go", "internal/command/stackpreset/preset_ids_generated.go"}
				before := make([][]byte, len(paths))
				for index, path := range paths {
					var err error
					before[index], err = os.ReadFile(filepath.Join(root, path))
					if err != nil {
						t.Fatal(err)
					}
				}
				command := exec.CommandContext(ctx, binary, "--check")
				command.Dir = root
				output, err := command.CombinedOutput()
				if err != nil || len(output) != 0 {
					t.Fatal("valid --check failed or emitted output")
				}
				for index, path := range paths {
					after, err := os.ReadFile(filepath.Join(root, path))
					if err != nil || !bytes.Equal(before[index], after) {
						t.Fatal("--check changed a generated projection")
					}
				}
			})
		})
	}
}
