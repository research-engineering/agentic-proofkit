package workflowsmoke_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

const processHelperMode = "PROOFKIT_WORKFLOW_SMOKE_HELPER_MODE"

func TestVerifyAcceptsApplicationCLI(t *testing.T) {
	if err := workflowsmoke.Verify(t.Context(), applicationRunner); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsCarrierContractMutations(t *testing.T) {
	mutations := []struct {
		name             string
		match            string
		matchPrefix      bool
		materializedOnly bool
		apply            func(workflowsmoke.Result) workflowsmoke.Result
	}{
		{name: "integration source identity", match: "integration source --tool codex --format json", apply: replaceStdout(`{"kind":"wrong"}`)},
		{name: "managed plan missing transaction", match: "integration plan --tool codex --operation install --repo-root ", matchPrefix: true, apply: replaceStdout(`{"kind":"proofkit.integration-plan.v1","state":"ready","transaction":null}`)},
		{name: "managed apply identity", match: "integration apply --tool codex --operation install --repo-root ", matchPrefix: true, apply: replaceStdoutFragment(`"kind": "proofkit.integration-receipt.v1"`, `"kind": "wrong"`)},
		{name: "managed recovery tool authority", match: "integration recover --repo-root ", matchPrefix: true, apply: replaceStdoutFragment(`"tool": null`, `"tool": "codex"`)},
		{name: "integration source text suffix", match: "integration source --tool claude --format text", apply: appendStdout("surplus\n")},
		{name: "integration missing promoted", match: "integration check --tool codex --repo-root ", matchPrefix: true, apply: func(result workflowsmoke.Result) workflowsmoke.Result {
			result.ExitCode = 0
			return result
		}},
		{name: "retired planner route", match: "change-workflow-plan --input -", apply: func(result workflowsmoke.Result) workflowsmoke.Result {
			return workflowsmoke.Result{ExitCode: 0, Stdout: []byte("{}\n")}
		}},
		{name: "planner identity", match: "change plan --input -", apply: replaceStdout(`{"reportKind":"wrong"}\n`)},
		{name: "workflow profile identity", match: "change plan --input -", apply: replaceStdoutFragment(`"workflowProfileId": "proofkit.reviewed-change.v1"`, `"workflowProfileId": "wrong"`)},
		{name: "compact layout", match: "--json-layout compact change plan --input -", apply: replaceStdout("{\n  \"reportKind\": \"proofkit.change-workflow-plan\"\n}\n")},
		{name: "envelope identity", match: "change plan --input - --agent-envelope", apply: replaceStdout(`{"envelopeId":"wrong"}\n`)},
		{name: "planner text styling", match: "change plan --input - --format text --color never", apply: replaceStdout("\x1b[31mChange workflow plan\x1b[0m\n")},
		{name: "planner text suffix", match: "change plan --input - --format text --color never", apply: appendStdout("surplus\n")},
		{name: "failure stdout", match: "change plan", apply: func(result workflowsmoke.Result) workflowsmoke.Result {
			result.Stdout = []byte("unexpected")
			return result
		}},
		{name: "guidance slots", match: "native-evidence-guidance", apply: replaceStdout(`{"guidanceId":"proofkit.native-evidence-guidance.v1","slots":[]}\n`)},
		{name: "guidance applicability", match: "native-evidence-guidance", apply: replaceStdoutFragment(`"applicabilityClass": "always"`, `"applicabilityClass": "external_process"`)},
		{name: "guidance middle slot", match: "native-evidence-guidance", apply: replaceStdoutFragment(`"slotId": "output_bounds"`, `"slotId": "wrong"`)},
		{name: "guidance text suffix", match: "native-evidence-guidance --format text --color never", apply: appendStdout("surplus\n")},
		{name: "project status identity", match: "status --repo-root ", matchPrefix: true, apply: replaceStdoutFragment(`"reportKind": "proofkit.project-status"`, `"reportKind": "wrong"`)},
		{name: "project next identity", match: "next --repo-root ", matchPrefix: true, apply: replaceStdoutFragment(`"packetKind": "proofkit.project-next-action"`, `"packetKind": "wrong"`)},
		{name: "materialized project status failure", match: "status --repo-root ", matchPrefix: true, materializedOnly: true, apply: func(result workflowsmoke.Result) workflowsmoke.Result {
			return workflowsmoke.Result{ExitCode: 1, Stderr: []byte("injected materialized-only failure\n")}
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			applied := false
			runner := func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
				result, err := applicationRunner(ctx, invocation)
				joined := strings.Join(invocation.Args, " ")
				matches := joined == mutation.match || (mutation.matchPrefix && strings.HasPrefix(joined, mutation.match))
				if matches && mutation.materializedOnly && !hasMaterializedProject(invocation) {
					matches = false
				}
				if err == nil && !applied && matches {
					result = mutation.apply(result)
					applied = true
				}
				return result, err
			}
			if err := workflowsmoke.Verify(t.Context(), runner); err == nil {
				t.Fatal("carrier mutation was accepted")
			}
			if !applied {
				t.Fatalf("mutation route %q was not exercised", mutation.match)
			}
		})
	}
}

func hasMaterializedProject(invocation workflowsmoke.Invocation) bool {
	for index := 0; index+1 < len(invocation.Args); index++ {
		if invocation.Args[index] != "--repo-root" {
			continue
		}
		_, err := os.Stat(filepath.Join(invocation.Args[index+1], filepath.FromSlash(adoptionmaterialization.ProjectManifestPath)))
		return err == nil
	}
	return false
}

func TestRunProcessRejectsTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	_, err := workflowsmoke.RunProcess(ctx, helperCarrier("hang"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v, want context deadline", err)
	}
}

func TestRunProcessRejectsOutputOverflow(t *testing.T) {
	for _, test := range []struct {
		mode string
		want string
	}{
		{mode: "stdout-overflow", want: "stdout exceeds"},
		{mode: "stderr-overflow", want: "stderr exceeds"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := workflowsmoke.RunProcess(ctx, helperCarrier(test.mode), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("overflow error=%v, want %s", err, test.want)
			}
		})
	}
}

func TestRunProcessAcceptsExactOutputBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := workflowsmoke.RunProcess(ctx, helperCarrier("output-boundary"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Stdout) != 256*1024 || len(result.Stderr) != 64*1024 {
		t.Fatalf("output lengths=(%d,%d), want (%d,%d)", len(result.Stdout), len(result.Stderr), 256*1024, 64*1024)
	}
}

func TestRunProcessCustomOutputLimitsAreExact(t *testing.T) {
	const stdoutBytes = 1024
	const stderrBytes = 128
	invocation := workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes}
	tests := []struct {
		name   string
		limits workflowsmoke.ProcessOutputLimits
		want   string
	}{
		{name: "exact", limits: workflowsmoke.ProcessOutputLimits{MaximumStdoutBytes: stdoutBytes, MaximumStderrBytes: stderrBytes}},
		{name: "stdout one over", limits: workflowsmoke.ProcessOutputLimits{MaximumStdoutBytes: stdoutBytes - 1, MaximumStderrBytes: stderrBytes}, want: "stdout exceeds"},
		{name: "stderr one over", limits: workflowsmoke.ProcessOutputLimits{MaximumStdoutBytes: stdoutBytes, MaximumStderrBytes: stderrBytes - 1}, want: "stderr exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result, err := workflowsmoke.RunProcessWithOutputLimits(ctx, helperCarrier("custom-output-boundary"), invocation, test.limits)
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("one-over custom output error=%v, want %s", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Stdout) != stdoutBytes || len(result.Stderr) != stderrBytes {
				t.Fatalf("output lengths=(%d,%d), want (%d,%d)", len(result.Stdout), len(result.Stderr), stdoutBytes, stderrBytes)
			}
		})
	}
}

func TestRunProcessRejectsInvalidCustomOutputLimitsBeforeStart(t *testing.T) {
	for _, limits := range []workflowsmoke.ProcessOutputLimits{
		{},
		{MaximumStdoutBytes: 0, MaximumStderrBytes: 1},
		{MaximumStdoutBytes: 1, MaximumStderrBytes: 0},
		{MaximumStdoutBytes: (8 << 20) + 1, MaximumStderrBytes: 1},
		{MaximumStdoutBytes: 1, MaximumStderrBytes: 9 << 20},
	} {
		if _, err := workflowsmoke.RunProcessWithOutputLimits(t.Context(), helperCarrier("hang"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes}, limits); err == nil {
			t.Fatalf("invalid limits %#v were accepted", limits)
		}
	}
	if _, err := workflowsmoke.RunProcessWithOutputLimits(t.Context(), helperCarrier("no-read"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes}, workflowsmoke.ProcessOutputLimits{
		MaximumStdoutBytes: 8 << 20,
		MaximumStderrBytes: 8 << 20,
	}); err != nil {
		t.Fatalf("exact package hard limits were rejected: %v", err)
	}
}

func TestRunProcessProvesUnreadStdin(t *testing.T) {
	t.Run("non-reader exits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		result, err := workflowsmoke.RunProcess(ctx, helperCarrier("no-read"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinMustRemainUnread})
		if err != nil {
			t.Fatal(err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("exit code=%d want 0", result.ExitCode)
		}
	})
	t.Run("reader blocks", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		_, err := workflowsmoke.RunProcess(ctx, helperCarrier("read-stdin"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinMustRemainUnread})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stdin-read error=%v, want context deadline", err)
		}
	})
}

func TestWorkflowSmokeProcessHelper(t *testing.T) {
	mode := os.Getenv(processHelperMode)
	if mode == "" {
		return
	}
	switch mode {
	case "hang":
		time.Sleep(time.Hour)
	case "stdout-overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 512*1024))
	case "stderr-overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 128*1024))
	case "output-boundary":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 256*1024))
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 64*1024))
	case "custom-output-boundary":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 1024))
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 128))
	case "read-stdin":
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "no-read":
	case "spawn-descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestWorkflowSmokeProcessHelper$", "--")
		child.Env = append(os.Environ(), processHelperMode+"=hang")
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "start descendant failed")
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, child.Process.Pid)
		_ = child.Process.Release()
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unsupported helper mode")
		os.Exit(2)
	}
	os.Exit(0)
}

func applicationRunner(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
	var stdin io.Reader = bytes.NewReader(invocation.Input)
	if invocation.StdinClass == workflowsmoke.StdinMustRemainUnread {
		stdin = unreadableReader{}
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := app.Run(ctx, invocation.Args, stdin, &stdout, &stderr)
	return workflowsmoke.Result{ExitCode: exitCode, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

type unreadableReader struct{}

func (unreadableReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("stdin must remain unread")
}

func helperCarrier(mode string) workflowsmoke.ProcessCarrier {
	return workflowsmoke.ProcessCarrier{
		Executable:  os.Args[0],
		Prefix:      []string{"-test.run=^TestWorkflowSmokeProcessHelper$", "--"},
		Environment: append(os.Environ(), processHelperMode+"="+mode),
	}
}

func replaceStdout(value string) func(workflowsmoke.Result) workflowsmoke.Result {
	return func(result workflowsmoke.Result) workflowsmoke.Result {
		result.Stdout = []byte(value)
		return result
	}
}

func replaceStdoutFragment(oldValue string, newValue string) func(workflowsmoke.Result) workflowsmoke.Result {
	return func(result workflowsmoke.Result) workflowsmoke.Result {
		result.Stdout = bytes.Replace(result.Stdout, []byte(oldValue), []byte(newValue), 1)
		return result
	}
}

func appendStdout(value string) func(workflowsmoke.Result) workflowsmoke.Result {
	return func(result workflowsmoke.Result) workflowsmoke.Result {
		result.Stdout = append(result.Stdout, value...)
		return result
	}
}
