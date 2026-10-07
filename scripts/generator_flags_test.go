package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/gitfixture"
)

func TestGeneratorFlagDiagnosticsPreserveProcessContract(t *testing.T) {
	root := sourceHygieneRepoRoot(t)
	secret := strings.Join([]string{"api", "_key=", "synthetic-generator-fixture"}, "")
	protectedFlag := strings.Join([]string{"gh", "p_", strings.Repeat("x", 36)}, "")
	for _, tool := range []string{"commandcontractgen", "commandfamilygen"} {
		t.Run(tool, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), tool)
			setupCtx, cancelSetup := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancelSetup()
			build := exec.CommandContext(setupCtx, "go", "build", "-o", binary, "./internal/tools/"+tool)
			build.Dir = root
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build failed: %v\n%s", err, output)
			}
			directory := generatorSourceFixture(t, setupCtx, root)
			cancelSetup()
			outputs := []string{"internal/app/command_family_catalog_generated.go"}
			modeError := "commandfamilygen accepts only --check\n"
			staleError := "generated command family projection is stale; run go run ./internal/tools/commandfamilygen\n"
			if tool == "commandcontractgen" {
				outputs = []string{"internal/app/command_contract_generated.go", "internal/command/stackpreset/preset_ids_generated.go"}
				modeError = "commandcontractgen accepts either --check or --refresh-structures\n"
				staleError = "application projection is stale; run go run ./internal/tools/commandcontractgen\n"
			}
			original, stale := make(map[string][]byte), make(map[string][]byte)
			for _, name := range outputs {
				content, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				original[name] = content
				stale[name] = append(append([]byte(nil), content...), []byte("\n// Deliberately stale projection fixture.\n")...)
			}
			resetOutputs := func(t *testing.T) {
				t.Helper()
				for _, name := range outputs {
					if err := os.WriteFile(filepath.Join(directory, name), stale[name], 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			assertOutputs := func(t *testing.T, wantStale bool) {
				t.Helper()
				for _, name := range outputs {
					expected := stale[name]
					if !wantStale {
						expected = original[name]
					}
					actual, err := os.ReadFile(filepath.Join(directory, name))
					if err != nil || !bytes.Equal(actual, expected) {
						t.Fatal("generation output observation changed")
					}
				}
			}
			run := func(t *testing.T, args []string, argvZero string, wantExit int, wantStderr string) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				command := exec.CommandContext(ctx, binary, args...)
				command.Dir = directory
				if argvZero != "" {
					command.Args[0] = argvZero
				}
				var stdout, stderr bytes.Buffer
				command.Stdout, command.Stderr = &stdout, &stderr
				err := command.Run()
				var exitErr *exec.ExitError
				if err != nil && !errors.As(err, &exitErr) {
					t.Fatalf("process did not complete: %v", err)
				}
				if code := command.ProcessState.ExitCode(); code != wantExit {
					t.Fatalf("exit=%d, want %d; diagnostic=%s", code, wantExit, diagnostic.Text(errors.New(strings.TrimSuffix(stderr.String(), "\n"))))
				}
				if strings.Contains(stderr.String(), "synthetic-generator-fixture") || strings.Contains(stderr.String(), protectedFlag) {
					t.Fatal("protected caller text escaped the diagnostic boundary")
				}
				if stdout.Len() != 0 || stderr.String() != wantStderr {
					t.Fatal("exact stdout/stderr contract mismatch")
				}
			}
			// A real successful write proves the early-exit fixture is not vacuous.
			resetOutputs(t)
			run(t, nil, "", 0, "")
			assertOutputs(t, false)
			run(t, []string{"--check"}, "", 0, "")
			assertOutputs(t, false)
			t.Log("positive generation and check observations passed")

			type diagnosticCase struct {
				name   string
				args   []string
				exit   int
				stderr string
			}
			tests := []diagnosticCase{
				{"help-long", []string{"--help"}, 0, ""},
				{"help-short", []string{"-h"}, 0, ""},
				{"invalid-boolean", []string{"--check=not-a-boolean"}, 2, ""},
				{"unknown-flag", []string{"--unknown"}, 2, ""},
				{"positional", []string{"unexpected"}, 1, modeError},
				{"protected-boolean", []string{"--check=" + secret}, 2, "<redacted-diagnostic-value>\n"},
				{"protected-flag-name", []string{"--" + protectedFlag}, 2, "<redacted-diagnostic-value>\n"},
				{"protected-positional", []string{secret}, 1, modeError},
				{"caller-newline", []string{"--unknown\nFORGED"}, 2, "<redacted-diagnostic-value>\n"},
				{"caller-tab", []string{"--unknown\tFORGED"}, 2, "<redacted-diagnostic-value>\n"},
				{"caller-bad-syntax", []string{"---unknown\nFORGED"}, 2, "<redacted-diagnostic-value>\n"},
				{"check-stale-projection", []string{"--check"}, 1, staleError},
			}
			if tool == "commandcontractgen" {
				tests = append(tests, diagnosticCase{"combined-modes", []string{"--check", "--refresh-structures"}, 1, modeError})
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					expected := test.stderr
					if expected == "" {
						expected = expectedGeneratorFlagDiagnostic(tool, test.args)
					}
					resetOutputs(t)
					run(t, test.args, "", test.exit, expected)
					assertOutputs(t, true)
				})
			}
			t.Run("caller-argv-zero-is-not-usage-authority", func(t *testing.T) {
				resetOutputs(t)
				run(t, []string{"--help"}, "caller\n\t"+secret, 0, expectedGeneratorFlagDiagnostic(tool, []string{"--help"}))
				assertOutputs(t, true)
			})
		})
	}
}

func expectedGeneratorFlagDiagnostic(tool string, args []string) string {
	set := flag.NewFlagSet(tool, flag.ContinueOnError)
	if tool == "commandcontractgen" {
		set.Bool("check", false, "verify both generated command-contract projections")
		set.Bool("refresh-structures", false, "refresh native structural definitions and both generated projections")
	} else {
		set.Bool("check", false, "verify that the generated projection is current")
	}
	var output bytes.Buffer
	set.SetOutput(&output)
	_ = set.Parse(args)
	return output.String()
}

func generatorSourceFixture(t *testing.T, ctx context.Context, root string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "ls-files", "-z")
	command.Dir = root
	files, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for _, name := range strings.Split(string(files), "\x00") {
		if name == "" {
			continue
		}
		if !fs.ValidPath(name) {
			t.Fatal("invalid tracked source path")
		}
		source := filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Lstat(source)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("fixture source must be a regular file")
		}
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "--force", "--all"}} {
		if output, err := gitfixture.Command(directory, args...).CombinedOutput(); err != nil {
			t.Fatalf("initialize isolated source fixture: %v; diagnostic=%s", err, diagnostic.Text(errors.New(strings.TrimSuffix(string(output), "\n"))))
		}
	}
	indexed, err := gitfixture.Command(directory, "ls-files", "-z").Output()
	if err != nil || !bytes.Equal(indexed, files) {
		t.Fatal("isolated fixture changed the tracked source inventory")
	}
	return directory
}
