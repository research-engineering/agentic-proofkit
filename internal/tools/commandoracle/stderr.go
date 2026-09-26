package commandoracle

import (
	"errors"
	"io"
	"os"
	"time"
)

// commandStderr separates complete observation from intentional failure cleanup.
// Only the command coordinator mutates its state; the copier publishes one result.
type commandStderr struct {
	reader   io.ReadCloser
	bounded  *boundedDrain
	done     chan error
	timer    *time.Timer
	deadline <-chan time.Time
	copyErr  error
	closeErr error
	aborted  bool
	expired  bool
	closed   bool
}

func startCommandStderr(reader io.ReadCloser) *commandStderr {
	drain := &commandStderr{
		reader:  reader,
		bounded: newBoundedDrain(),
		done:    make(chan error, 1),
	}
	done := drain.done
	go func() {
		_, err := io.Copy(drain.bounded, reader)
		done <- err
	}()
	return drain
}

func (drain *commandStderr) receive(err error) {
	drain.done = nil
	drain.stopTimer()
	if err != nil && !(drain.aborted && errors.Is(err, os.ErrClosed)) {
		drain.copyErr = errors.New("command oracle stderr copy failed")
	}
}

func (drain *commandStderr) parentWaited() {
	if drain.done != nil && !drain.aborted && drain.timer == nil {
		drain.timer = time.NewTimer(processWaitDelay)
		drain.deadline = drain.timer.C
	}
}

func (drain *commandStderr) expire() {
	if drain.done == nil {
		return
	}
	// A queued completion takes precedence over a simultaneously ready timer.
	select {
	case err := <-drain.done:
		drain.receive(err)
		return
	default:
	}
	drain.expired = true
	drain.abort()
}

func (drain *commandStderr) abort() {
	drain.aborted = true
	drain.stopTimer()
	drain.close()
}

func (drain *commandStderr) close() {
	if !drain.closed {
		drain.closed = true
		if err := drain.reader.Close(); err != nil {
			drain.closeErr = errors.New("command oracle stderr reader close failed")
		}
	}
}

func (drain *commandStderr) stopTimer() {
	if drain.timer != nil {
		drain.timer.Stop()
		drain.timer = nil
	}
	drain.deadline = nil
}

func (drain *commandStderr) failure() error {
	var incomplete error
	if drain.done != nil || !drain.closed || drain.aborted || drain.expired {
		incomplete = errors.New("command oracle stderr observation incomplete")
	}
	return errors.Join(incomplete, drain.copyErr, drain.closeErr)
}

func withCommandFailures(primary error, failures ...error) error {
	secondary := errors.Join(failures...)
	if secondary == nil {
		return primary
	}
	if primary == nil {
		primary = decision("process.suite_failed")
	}
	return errors.Join(primary, secondary)
}
