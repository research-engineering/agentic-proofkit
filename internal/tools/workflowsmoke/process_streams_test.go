//go:build darwin || linux

package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"
)

func TestOwnedFiniteStdinPreservesEPIPEAndChildResult(t *testing.T) {
	for _, test := range []struct {
		name, body string
		input      []byte
		code       int
		output     string
	}{
		{name: "nil_stdin", body: "exec /bin/cat"},
		{name: "finite_copy", body: "exec /bin/cat", input: []byte("finite\n"), output: "finite\n"},
		{name: "early_success", body: "exit 0", input: bytes.Repeat([]byte{'x'}, 1<<20)},
		{name: "early_failure", body: "exit 7", input: bytes.Repeat([]byte{'x'}, 1<<20), code: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result, err := RunProcess(ctx, ProcessCarrier{Executable: "/bin/sh", Prefix: []string{"-c", test.body}}, Invocation{StdinClass: StdinBytes, Input: test.input})
			if err != nil || result.ExitCode != test.code || string(result.Stdout) != test.output {
				t.Fatalf("stdin result: %+v %v", result, err)
			}
		})
	}
}

type failingOutput struct{}

var errCopyControl = errors.New("synthetic copy failure")

func (failingOutput) Write([]byte) (int, error) { return 0, errCopyControl }

func TestOwnedCopyFailureDoesNotBecomeExitSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := exec.Command("/bin/sh", "-c", "printf output; exec /bin/sleep 2")
	_, cleanupErr, streamErr := runCarrierStreams(ctx, command, Invocation{StdinClass: StdinBytes}, failingOutput{}, io.Discard)
	if cleanupErr != nil || !errors.Is(streamErr, errCopyControl) || ctx.Err() != nil {
		t.Fatalf("copy failure lost, conflated with cleanup or delayed: %v %v %v", cleanupErr, streamErr, ctx.Err())
	}
}
