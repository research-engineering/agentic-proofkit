package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

// This protocol owns only the cancellation carrier's registration, dispatch-release,
// signal-sent, and independent child-exit witnesses. Product branch events stay in trace.
type npmBranchControl struct {
	readyReader, readyWriter     *os.File
	commandReader, commandWriter *os.File
	eventReader, eventWriter     *os.File
	releaseReader, releaseWriter *os.File
	signalReader, signalWriter   *os.File
	finished                     bool
}

func newNPMBranchControl(t *testing.T) *npmBranchControl {
	t.Helper()
	control := &npmBranchControl{}
	t.Cleanup(control.close)
	deadline := time.Now().Add(5 * time.Second)
	for _, pair := range []struct{ reader, writer **os.File }{
		{&control.readyReader, &control.readyWriter},
		{&control.commandReader, &control.commandWriter},
		{&control.eventReader, &control.eventWriter},
		{&control.releaseReader, &control.releaseWriter},
		{&control.signalReader, &control.signalWriter},
	} {
		var err error
		*pair.reader, *pair.writer, err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := (*pair.reader).SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if err := (*pair.writer).SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	return control
}

func (control *npmBranchControl) closeChildEnds() {
	_ = control.readyWriter.Close()
	_ = control.commandReader.Close()
	_ = control.eventWriter.Close()
	_ = control.releaseReader.Close()
	_ = control.signalReader.Close()
}

func (control *npmBranchControl) close() {
	for _, file := range []*os.File{control.readyReader, control.readyWriter, control.commandReader, control.commandWriter, control.eventReader, control.eventWriter, control.releaseReader, control.releaseWriter, control.signalReader, control.signalWriter} {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (control *npmBranchControl) event(want byte) error {
	return npmBranchMarker(control.eventReader, want)
}

func npmBranchMarker(reader *os.File, want byte) error {
	var marker [1]byte
	if _, err := io.ReadFull(reader, marker[:]); err != nil {
		return fmt.Errorf("carrier marker %q unavailable: %w", want, err)
	}
	if marker[0] != want {
		return fmt.Errorf("carrier marker=%q, want %q", marker[0], want)
	}
	return nil
}

func (control *npmBranchControl) command(value string) error {
	_, err := io.WriteString(control.commandWriter, value+"\n")
	return err
}

// cmd.Cancel sends its SIGTERM only through signalCarrier: it calls send, and
// only after send has returned does it close the signal-sent pipe. The signal
// is then pending in Bash before Bash can read EOF from this pipe, so a read
// that ends at this EOF is followed by the trap, never by the next command. A
// nil control only sends.
func (control *npmBranchControl) signalCarrier(send func() error) error {
	err := send()
	if control != nil {
		_ = control.signalWriter.Close()
	}
	return err
}

// npmBranchSignalPipeOpen reads the signal-sent pipe without blocking: EAGAIN
// means its writer is still open, EOF means it was already closed.
func npmBranchSignalPipeOpen(reader *os.File) error {
	connection, err := reader.SyscallConn()
	if err != nil {
		return err
	}
	var state error
	err = connection.Read(func(fd uintptr) bool {
		n, readError := syscall.Read(int(fd), make([]byte, 1))
		if errors.Is(readError, syscall.EAGAIN) {
			return true
		}
		if readError == nil && n == 0 {
			state = fmt.Errorf("signal-sent pipe closed before the signal")
		} else {
			state = fmt.Errorf("signal-sent pipe state n=%d err=%v", n, readError)
		}
		return true
	})
	return errors.Join(state, err)
}

func (control *npmBranchControl) release() error {
	if control.releaseWriter == nil {
		return nil
	}
	_, writeError := control.releaseWriter.Write([]byte{1})
	closeError := control.releaseWriter.Close()
	control.releaseWriter = nil
	return errors.Join(writeError, closeError)
}

func (control *npmBranchControl) run(item npmBranchCase, cancel func() error) error {
	if item.delayedChildStartup {
		if err := control.event('T'); err != nil {
			return err
		}
		if err := control.command("start"); err != nil {
			return err
		}
	}
	if err := control.event('S'); err != nil {
		return err
	}
	// Produce readiness while Bash is held before child=$!, then independently
	// control when the cancellation observer consumes that notification.
	ready := make(chan error, 1)
	produced := make(chan struct{})
	go func() {
		ready <- npmBranchMarker(control.readyReader, 1)
		close(produced)
	}()
	<-produced
	if !item.lateReadyObservation {
		if err := <-ready; err != nil {
			return err
		}
	}
	if err := control.command("register"); err != nil {
		return err
	}
	if err := control.event('P'); err != nil {
		return err
	}
	if item.lateReadyObservation {
		if err := <-ready; err != nil {
			return err
		}
	}
	if item.pendingSignalAtBlock {
		// Bash is expanding the redirection of its blocking read, past its last
		// trap check before that read, so the signal arrives as a pending trap.
		if err := control.event('E'); err != nil {
			return err
		}
	}
	if err := cancel(); err != nil {
		return err
	}
	for _, event := range []byte{'C', 'W'} {
		if err := control.event(event); err != nil {
			return err
		}
	}
	// Keep the mutant's classifier blocked until its claimed wait completion.
	// Thus retaining the same 'reaped' printf cannot satisfy the exit oracle.
	if !item.removeCleanupWait {
		if err := control.release(); err != nil {
			return err
		}
	}
	if err := control.event('D'); err != nil {
		return err
	}
	oracleError := npmBranchClassifierExit(control.readyReader)
	if item.removeCleanupWait {
		if err := control.release(); err != nil {
			return errors.Join(oracleError, err)
		}
		// Recover the intentionally faulty carrier before permitting shell exit.
		if err := npmBranchMarker(control.readyReader, 2); err != nil {
			return errors.Join(oracleError, err)
		}
		if _, err := control.readyReader.Read(make([]byte, 1)); err != io.EOF {
			return errors.Join(oracleError, fmt.Errorf("classifier recovery did not close readiness: %v", err))
		}
	}
	if err := control.command("finish"); err != nil {
		return errors.Join(oracleError, err)
	}
	control.finished = true
	return oracleError
}

// Bash and the controller close their copies of the readiness writer. Only the
// classifier retains it until os.Exit, after its successful main-return marker.
// A nonblocking kernel read separates actual exit from stdio-drain completion.
func npmBranchClassifierExit(reader *os.File) error {
	connection, err := reader.SyscallConn()
	if err != nil {
		return err
	}
	var oracleError error
	err = connection.Read(func(fd uintptr) bool {
		var marker [1]byte
		n, readError := syscall.Read(int(fd), marker[:])
		if errors.Is(readError, syscall.EAGAIN) {
			oracleError = fmt.Errorf("carrier cleanup did not wait for classifier exit")
			return true
		}
		if readError != nil || n != 1 || marker[0] != 2 {
			oracleError = fmt.Errorf("classifier exited without completing admission")
			return true
		}
		n, readError = syscall.Read(int(fd), marker[:])
		if readError != nil || n != 0 {
			oracleError = fmt.Errorf("carrier cleanup did not wait for classifier exit")
		}
		return true
	})
	return errors.Join(oracleError, err)
}
