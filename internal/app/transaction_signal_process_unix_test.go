//go:build darwin || linux

package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const transactionSignalHelperEnvironment = "PROOFKIT_TRANSACTION_SIGNAL_TEST_HELPER"

type transactionSignalCase struct {
	Mode     string
	Args     []string
	Input    []byte
	Canceled bool
	ExitCode int
}

type transactionSignalProcess struct {
	command *exec.Cmd
	context context.Context
	acks    *bufio.Reader
	control *os.File
	stdin   *os.File
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	waited  bool
}

func startTransactionSignalProcess(t *testing.T, test transactionSignalCase) *transactionSignalProcess {
	t.Helper()
	encoded, err := json.Marshal(test)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "case.json")
	if err := os.WriteFile(config, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	pipe := func() (*os.File, *os.File) {
		t.Helper()
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
		return read, write
	}
	ackRead, ackWrite := pipe()
	controlRead, controlWrite := pipe()
	stdinRead, stdinWrite := pipe()
	deadline := time.Now().Add(15 * time.Second)
	for _, file := range []*os.File{ackRead, controlWrite, stdinWrite} {
		if err := file.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	process := &transactionSignalProcess{context: ctx, acks: bufio.NewReader(ackRead), control: controlWrite, stdin: stdinWrite}
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTransactionSignalHelper$", "-test.count=1")
	process.command = command
	command.Env = append(os.Environ(), transactionSignalHelperEnvironment+"="+config)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.ExtraFiles = []*os.File{ackWrite, controlRead}
	command.Stdin, command.Stdout, command.Stderr = stdinRead, &process.stdout, &process.stderr
	command.WaitDelay = 2 * time.Second
	t.Cleanup(func() {
		if command.Process != nil && !process.waited {
			_ = command.Process.Kill()
			_ = command.Wait()
			process.waited = true
		}
		cancel()
	})
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{ackWrite, controlRead, stdinRead} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return process
}

func (process *transactionSignalProcess) expect(t *testing.T, expected string) {
	t.Helper()
	line, err := process.acks.ReadString('\n')
	if err != nil || line != expected+"\n" {
		t.Fatalf("signal protocol: got %q err=%v, want %q", line, err, expected)
	}
}

func (process *transactionSignalProcess) send(t *testing.T, message string) {
	t.Helper()
	if _, err := fmt.Fprintln(process.control, message); err != nil {
		t.Fatal(err)
	}
}

func (process *transactionSignalProcess) signal(t *testing.T, signal syscall.Signal) {
	t.Helper()
	if process.waited {
		t.Fatal("cannot signal a reaped helper")
	}
	if err := process.command.Process.Signal(signal); err != nil {
		t.Fatal(err)
	}
}

func (process *transactionSignalProcess) wait(t *testing.T) syscall.WaitStatus {
	t.Helper()
	if process.waited {
		t.Fatal("helper already reaped")
	}
	process.waited = true
	err := process.command.Wait()
	if process.context.Err() != nil {
		t.Fatalf("helper watchdog expired, not signal-under-test success: %v", process.context.Err())
	}
	var exitError *exec.ExitError
	if err != nil && !errors.As(err, &exitError) {
		t.Fatalf("helper wait: %v", err)
	}
	status, ok := process.command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatal("native wait status unavailable")
	}
	return status
}

func (process *transactionSignalProcess) expectExit(t *testing.T, code int) {
	t.Helper()
	status := process.wait(t)
	if !status.Exited() || status.ExitStatus() != code {
		t.Fatalf("exit status=%v want=%d stdout=%q stderr=%q", status, code, process.stdout.String(), process.stderr.String())
	}
}

func (process *transactionSignalProcess) expectSignal(t *testing.T, signal syscall.Signal) {
	t.Helper()
	status := process.wait(t)
	if !status.Signaled() || status.Signal() != signal {
		t.Fatalf("termination=%v want signal=%v stdout=%q stderr=%q", status, signal, process.stdout.String(), process.stderr.String())
	}
	if process.stdout.Len() != 0 || process.stderr.Len() != 0 {
		t.Fatalf("blocked helper emitted product output: %q %q", process.stdout.String(), process.stderr.String())
	}
}

type transactionSignalWire struct {
	t       *testing.T
	acks    *os.File
	control *bufio.Reader
}

func (wire transactionSignalWire) ack(message string) {
	wire.t.Helper()
	if _, err := fmt.Fprintln(wire.acks, message); err != nil {
		wire.t.Fatal(err)
	}
}

func (wire transactionSignalWire) receive(expected string) {
	wire.t.Helper()
	line, err := wire.control.ReadString('\n')
	if err != nil || line != expected+"\n" {
		wire.t.Fatalf("helper control: %q %v, want %q", line, err, expected)
	}
}

type transactionSignalBlockedWriter struct{ wire transactionSignalWire }

func (writer transactionSignalBlockedWriter) Write(content []byte) (int, error) {
	writer.wire.ack("BLOCKED")
	writer.wire.receive("RELEASE")
	return os.Stdout.Write(content)
}

type transactionSignalInputReader struct {
	wire    transactionSignalWire
	entered bool
}

func (reader *transactionSignalInputReader) Read(content []byte) (int, error) {
	if !reader.entered {
		reader.entered = true
		reader.wire.ack("INPUT_ENTERED")
	}
	return os.Stdin.Read(content)
}

// Only the test binary accepts this helper protocol; production has no test flags.
func TestTransactionSignalHelper(t *testing.T) {
	path := os.Getenv(transactionSignalHelperEnvironment)
	if path == "" {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var test transactionSignalCase
	if err := json.Unmarshal(content, &test); err != nil {
		t.Fatal(err)
	}
	wire := transactionSignalWire{t: t, acks: os.NewFile(3, "ack"), control: bufio.NewReader(os.NewFile(4, "control"))}
	os.Exit(runTransactionSignalHelper(t, test, wire))
}

func runTransactionSignalHelper(t *testing.T, test transactionSignalCase, wire transactionSignalWire) int {
	switch test.Mode {
	case "writer", "operation":
		scope := newTransactionSignalScope(context.Background())
		reported := make(chan struct{})
		go func() {
			<-scope.restored
			wire.ack("RESTORED")
			close(reported)
		}()
		defer func() { scope.Close(); <-reported }()
		wire.ack("ARMED")
		var output io.Writer = transactionSignalBlockedWriter{wire: wire}
		if test.Mode == "operation" {
			wire.ack("BLOCKED")
			wire.receive("RELEASE")
			output = os.Stdout
		}
		if _, err := io.WriteString(output, "owner-selected\n"); err != nil {
			t.Fatal(err)
		}
		return test.ExitCode
	case "app":
		ctx := context.Background()
		if test.Canceled {
			scope := newTransactionSignalScope(ctx)
			wire.ack("ARMED")
			<-scope.Done()
			<-scope.restored
			if !errors.Is(scope.Err(), context.Canceled) {
				t.Fatal("native signal did not cancel context")
			}
			ctx = scope.Context
			scope.Close()
			wire.ack("RESTORED")
		} else {
			wire.ack("ARMED")
		}
		wire.receive("GO")
		return Run(ctx, test.Args, bytes.NewReader(test.Input), os.Stdout, os.Stderr)
	case "stdin":
		return Run(context.Background(), test.Args, &transactionSignalInputReader{wire: wire}, os.Stdout, os.Stderr)
	default:
		t.Fatalf("unknown helper mode %q", test.Mode)
		return 1
	}
}

var transactionTestSignals = []struct {
	name   string
	signal syscall.Signal
}{{"INT", syscall.SIGINT}, {"TERM", syscall.SIGTERM}}

func TestTransactionSignalScopeFirstSignalRestores(t *testing.T) {
	for _, mode := range []string{"writer", "operation"} {
		for _, first := range transactionTestSignals {
			for _, code := range []int{0, 1} {
				t.Run(fmt.Sprintf("%s/%s/exit%d", mode, first.name, code), func(t *testing.T) {
					process := startTransactionSignalProcess(t, transactionSignalCase{Mode: mode, ExitCode: code})
					process.expect(t, "ARMED")
					process.expect(t, "BLOCKED")
					process.signal(t, first.signal)
					process.expect(t, "RESTORED")
					process.send(t, "RELEASE")
					process.expectExit(t, code)
					if process.stdout.String() != "owner-selected\n" || process.stderr.Len() != 0 {
						t.Fatal("first signal changed owner-selected output")
					}
				})
			}
		}
	}
}

func TestTransactionSignalScopeSecondSignal(t *testing.T) {
	for _, mode := range []string{"writer", "operation"} {
		for _, first := range transactionTestSignals {
			for _, second := range transactionTestSignals {
				t.Run(strings.Join([]string{mode, first.name, second.name}, "/"), func(t *testing.T) {
					process := startTransactionSignalProcess(t, transactionSignalCase{Mode: mode})
					process.expect(t, "ARMED")
					process.expect(t, "BLOCKED")
					process.signal(t, first.signal)
					process.expect(t, "RESTORED")
					process.signal(t, second.signal)
					process.expectSignal(t, second.signal)
				})
			}
		}
	}
}

func TestTransactionSignalScopeNoSignal(t *testing.T) {
	for _, mode := range []string{"writer", "operation"} {
		t.Run(mode, func(t *testing.T) {
			process := startTransactionSignalProcess(t, transactionSignalCase{Mode: mode})
			process.expect(t, "ARMED")
			process.expect(t, "BLOCKED")
			process.send(t, "RELEASE")
			process.expectExit(t, 0)
			if process.stdout.String() != "owner-selected\n" || process.stderr.Len() != 0 {
				t.Fatal("no-signal output changed")
			}
		})
	}
}
