package workflowsmoke_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/app"
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
		name  string
		match string
		apply func(workflowsmoke.Result) workflowsmoke.Result
	}{
		{name: "planner identity", match: "change-workflow-plan --input -", apply: replaceStdout(`{"reportKind":"wrong"}\n`)},
		{name: "workflow profile identity", match: "change-workflow-plan --input -", apply: replaceStdoutFragment(`"workflowProfileId": "proofkit.reviewed-change.v1"`, `"workflowProfileId": "wrong"`)},
		{name: "compact layout", match: "--json-layout compact change-workflow-plan --input -", apply: replaceStdout("{\n  \"reportKind\": \"proofkit.change-workflow-plan\"\n}\n")},
		{name: "envelope identity", match: "change-workflow-plan --input - --agent-envelope", apply: replaceStdout(`{"envelopeId":"wrong"}\n`)},
		{name: "planner text styling", match: "change-workflow-plan --input - --format text --color never", apply: replaceStdout("\x1b[31mChange workflow plan\x1b[0m\n")},
		{name: "planner text suffix", match: "change-workflow-plan --input - --format text --color never", apply: appendStdout("surplus\n")},
		{name: "failure stdout", match: "change-workflow-plan", apply: func(result workflowsmoke.Result) workflowsmoke.Result {
			result.Stdout = []byte("unexpected")
			return result
		}},
		{name: "guidance slots", match: "native-evidence-guidance", apply: replaceStdout(`{"guidanceId":"proofkit.native-evidence-guidance.v1","slots":[]}\n`)},
		{name: "guidance applicability", match: "native-evidence-guidance", apply: replaceStdoutFragment(`"applicabilityClass": "always"`, `"applicabilityClass": "external_process"`)},
		{name: "guidance middle slot", match: "native-evidence-guidance", apply: replaceStdoutFragment(`"slotId": "output_bounds"`, `"slotId": "wrong"`)},
		{name: "guidance text suffix", match: "native-evidence-guidance --format text --color never", apply: appendStdout("surplus\n")},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			applied := false
			runner := func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
				result, err := applicationRunner(ctx, invocation)
				if err == nil && !applied && strings.Join(invocation.Args, " ") == mutation.match {
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
	case "read-stdin":
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "no-read":
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
