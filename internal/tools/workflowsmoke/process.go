package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/processgroup"
)

const (
	processWaitDelay   = 2 * time.Second
	maximumStdoutBytes = 256 * 1024
	maximumStderrBytes = 64 * 1024
)

// ProcessCarrier identifies one installed executable and any fixed argv prefix.
type ProcessCarrier struct {
	Directory   string
	Executable  string
	Prefix      []string
	Environment []string
}

// VerifyProcess applies Verify to one installed process carrier.
func VerifyProcess(ctx context.Context, carrier ProcessCarrier) error {
	return Verify(ctx, func(ctx context.Context, invocation Invocation) (Result, error) {
		return RunProcess(ctx, carrier, invocation)
	})
}

// RunProcess executes one bounded carrier invocation. Output overflow and
// cancellation terminate the whole process group on supported Unix hosts.
func RunProcess(ctx context.Context, carrier ProcessCarrier, invocation Invocation) (Result, error) {
	if ctx == nil || carrier.Executable == "" {
		return Result{}, fmt.Errorf("process carrier requires a context and executable")
	}
	if invocation.StdinClass != StdinBytes && invocation.StdinClass != StdinMustRemainUnread {
		return Result{}, fmt.Errorf("process carrier received an unsupported stdin class")
	}
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	args := append(append([]string(nil), carrier.Prefix...), invocation.Args...)
	command := exec.CommandContext(processContext, carrier.Executable, args...)
	command.Dir = carrier.Directory
	command.WaitDelay = processWaitDelay
	if carrier.Environment != nil {
		command.Env = append([]string(nil), carrier.Environment...)
	}
	processgroup.Configure(command)
	stdout := newBoundedBuffer(maximumStdoutBytes, cancel)
	stderr := newBoundedBuffer(maximumStderrBytes, cancel)
	command.Stdout = stdout
	command.Stderr = stderr
	var stdinRead *os.File
	var stdinWrite *os.File
	if invocation.StdinClass == StdinMustRemainUnread {
		var err error
		stdinRead, stdinWrite, err = os.Pipe()
		if err != nil {
			return Result{}, fmt.Errorf("create unread-stdin oracle: %w", err)
		}
		defer stdinRead.Close()
		defer stdinWrite.Close()
		command.Stdin = stdinRead
	} else {
		command.Stdin = bytes.NewReader(invocation.Input)
	}
	err := command.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if stdout.Overflowed() {
		return Result{}, fmt.Errorf("process carrier stdout exceeds %d bytes", maximumStdoutBytes)
	}
	if stderr.Overflowed() {
		return Result{}, fmt.Errorf("process carrier stderr exceeds %d bytes", maximumStderrBytes)
	}
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("process carrier invocation canceled: %w", ctx.Err())
	}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return Result{}, fmt.Errorf("process carrier invocation failed: %w", err)
}

type boundedBuffer struct {
	mu       sync.Mutex
	content  []byte
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func newBoundedBuffer(limit int, cancel context.CancelFunc) *boundedBuffer {
	return &boundedBuffer{limit: limit, cancel: cancel}
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	remaining := buffer.limit - len(buffer.content)
	if remaining > 0 {
		count := len(value)
		if count > remaining {
			count = remaining
		}
		buffer.content = append(buffer.content, value[:count]...)
	}
	firstOverflow := len(value) > remaining && !buffer.overflow
	if len(value) > remaining {
		buffer.overflow = true
	}
	buffer.mu.Unlock()
	if firstOverflow {
		buffer.cancel()
	}
	return len(value), nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.content...)
}

func (buffer *boundedBuffer) Overflowed() bool {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.overflow
}
