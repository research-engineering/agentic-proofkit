package workflowsmoke

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/processgroup"
)

// All copiers have explicit close/join handles, even when identity loss forbids
// Cmd.Wait. Output and stdin policy remain local to the carrier.
func runCarrierStreams(ctx context.Context, command *exec.Cmd, invocation Invocation, stdout, stderr io.Writer) (error, error, error) {
	out, err := command.StdoutPipe()
	if err != nil {
		return err, nil, nil
	}
	defer out.Close()
	defer command.Stdout.(*os.File).Close()
	errout, err := command.StderrPipe()
	if err != nil {
		return err, nil, nil
	}
	defer errout.Close()
	defer command.Stderr.(*os.File).Close()
	var input, writer *os.File
	if invocation.StdinClass == StdinMustRemainUnread || invocation.Input != nil {
		input, writer, err = os.Pipe()
		if err != nil {
			return err, nil, nil
		}
		defer input.Close()
		defer writer.Close()
		command.Stdin = input
	}
	child, err := processgroup.Start(ctx, command)
	if err != nil {
		return err, nil, nil
	}
	var streamErr error
	record := func(err error) {
		if err != nil {
			streamErr = errors.Join(streamErr, err)
			_ = child.Abort()
		}
	}
	if input != nil {
		record(input.Close())
	}
	outDone, errDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := io.Copy(stdout, out); outDone <- err }()
	go func() { _, err := io.Copy(stderr, errout); errDone <- err }()
	var inputDone chan error
	if writer != nil && invocation.StdinClass == StdinBytes {
		inputDone = make(chan error, 1)
		go func() {
			_, copyErr := io.Copy(writer, bytes.NewReader(invocation.Input))
			// Match os/exec's ordinary early-exit stdin semantics, not arbitrary
			// copy failures. Non-EPIPE failures still fail the invocation.
			if errors.Is(copyErr, syscall.EPIPE) {
				copyErr = nil
			}
			closeErr := writer.Close()
			if errors.Is(closeErr, os.ErrClosed) {
				closeErr = nil
			}
			inputDone <- errors.Join(copyErr, closeErr)
		}()
	}
	terminal, abort := child.Terminal(), child.Aborted()
	terminalSeen, aborted := false, false
	var timer *time.Timer
	var deadline <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	outClosed, erroutClosed := false, false
	closeOutput := func() {
		if !outClosed {
			outClosed = true
			record(out.Close())
		}
		if !erroutClosed {
			erroutClosed = true
			record(errout.Close())
		}
	}
	closeInput := func() {
		if writer != nil {
			if err := writer.Close(); !errors.Is(err, os.ErrClosed) {
				record(err)
			}
		}
	}
	for outDone != nil || errDone != nil || inputDone != nil || (!terminalSeen && !aborted) {
		select {
		case err := <-outDone:
			outDone = nil
			if !(aborted && errors.Is(err, os.ErrClosed)) {
				record(err)
			}
		case err := <-errDone:
			errDone = nil
			if !(aborted && errors.Is(err, os.ErrClosed)) {
				record(err)
			}
		case err := <-inputDone:
			inputDone = nil
			if !(aborted && errors.Is(err, os.ErrClosed)) {
				record(err)
			}
		case <-terminal:
			terminalSeen, terminal = true, nil
			if invocation.StdinClass == StdinMustRemainUnread {
				closeInput()
			}
			if !aborted {
				timer = time.NewTimer(processWaitDelay)
				deadline = timer.C
			}
		case <-abort:
			aborted, abort = true, nil
			if timer != nil {
				timer.Stop()
			}
			deadline = nil
			closeOutput()
			closeInput()
		case <-deadline:
			deadline = nil
			// Admit already queued completions before classifying an expired drain.
			if outDone != nil {
				select {
				case err := <-outDone:
					outDone = nil
					record(err)
				default:
				}
			}
			if errDone != nil {
				select {
				case err := <-errDone:
					errDone = nil
					record(err)
				default:
				}
			}
			if inputDone != nil {
				select {
				case err := <-inputDone:
					inputDone = nil
					record(err)
				default:
				}
			}
			if outDone != nil || errDone != nil || inputDone != nil {
				record(exec.ErrWaitDelay)
			}
		}
	}
	// A close error is an abort reason before the lifecycle's final seal.
	closeOutput()
	waitErr, cleanupErr := child.Finish(processWaitDelay)
	// Non-EPIPE copier failures cannot become a successful ExitCode result just
	// because our abort produced an ExitError. Ordinary child exits still win
	// over EPIPE, which the stdin copier classified before reaching this point.
	return waitErr, cleanupErr, streamErr
}
