package commandoracle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/processgroup"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestExecuteBindsMaterializedSourceCandidatesAndRuntimeEvents(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	previousRunner := runSelectedTests
	runSelectedTests = emitPassingSelectedTestEvents
	t.Cleanup(func() { runSelectedTests = previousRunner })

	evidence, err := Execute(context.Background(), root)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(evidence.Candidates) == 0 || len(evidence.Record.Entries) != len(evidence.Candidates) {
		t.Fatalf("Execute() evidence is not candidate-closed: %#v", evidence.Record)
	}
	if evidence.Record.State != "passed" || !isSHA256(evidence.RecordDigest) || !isSHA256(evidence.Record.SourceSnapshotDigest) {
		t.Fatalf("Execute() identity is incomplete: %#v", evidence.Record)
	}
	if len(ExecutionCommandRefs(evidence)) == 0 || len(evidence.Record.ExecutionCommands) == 0 {
		t.Fatalf("Execute() command projection is incomplete: %#v", evidence.Record.ExecutionCommands)
	}
	if err := ValidateCurrent(context.Background(), root, evidence); err != nil {
		t.Fatalf("ValidateCurrent() rejected current evidence: %v", err)
	}
}

func TestValidateCurrentRejectsProducerUnreachableCandidateProjection(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	previousRunner := runSelectedTests
	runSelectedTests = emitPassingSelectedTestEvents
	t.Cleanup(func() { runSelectedTests = previousRunner })
	evidence, err := Execute(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	record := evidence.Record
	record.Entries = append([]JoinedEntry(nil), record.Entries...)
	record.Entries[0].Candidate.TestID += ".counterfeit"
	candidates := make([]app.CommandCoverageOracleCandidate, 0, len(record.Entries))
	for _, entry := range record.Entries {
		candidates = append(candidates, entry.Candidate)
	}
	record.CandidateSetDigest, err = CandidateSetDigest(candidates)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := EvidenceForRecord(record)
	if err != nil {
		t.Fatalf("counterfeit record must remain internally valid: %v", err)
	}
	if err := ValidateCurrent(context.Background(), root, mutated); DecisionID(err) != "current.candidate_projection_mismatch" {
		t.Fatalf("ValidateCurrent() error = %v, want current.candidate_projection_mismatch", err)
	}
}

func emitPassingSelectedTestEvents(_ context.Context, _ string, _ []ExecutionCommand, ledger *eventLedger) error {
	packages := make([]string, 0, len(ledger.packages))
	for packagePath := range ledger.packages {
		packages = append(packages, packagePath)
	}
	sort.Strings(packages)
	for _, packagePath := range packages {
		if err := ledger.observe(testEvent{Action: "start", Package: packagePath}); err != nil {
			return err
		}
	}
	tests := make([]selectedTestKey, 0, len(ledger.tests))
	for key := range ledger.tests {
		tests = append(tests, key)
	}
	sort.Slice(tests, func(left, right int) bool {
		return tests[left].Package+"\x00"+tests[left].Test < tests[right].Package+"\x00"+tests[right].Test
	})
	for _, key := range tests {
		if err := ledger.observe(testEvent{Action: "run", Package: key.Package, Test: key.Test}); err != nil {
			return err
		}
		attributes := make([]string, 0, len(ledger.expectedAttributes[key]))
		for attribute := range ledger.expectedAttributes[key] {
			attributes = append(attributes, attribute)
		}
		sort.Strings(attributes)
		for _, attribute := range attributes {
			if err := ledger.observe(testEvent{Action: "attr", Package: key.Package, Test: key.Test, Key: commandcoverage.ExecutionAttributeKey, Value: attribute}); err != nil {
				return err
			}
		}
		if err := ledger.observe(testEvent{Action: "pass", Package: key.Package, Test: key.Test}); err != nil {
			return err
		}
	}
	for _, packagePath := range packages {
		if err := ledger.observe(testEvent{Action: "pass", Package: packagePath}); err != nil {
			return err
		}
	}
	return nil
}

func TestRejectReservedAttributeForgeryRejectsDirectOwnerKeyUse(t *testing.T) {
	root := t.TempDir()
	path := "sample_test.go"
	source := `package sample

import "testing"

func TestForged(t *testing.T) {
	t.Attr("proofkit.command-oracle", "counterfeit")
}
`
	if err := os.WriteFile(filepath.Join(root, path), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectReservedAttributeForgery(root, []string{path}); DecisionID(err) != "source.reserved_attribute_direct_use" {
		t.Fatalf("rejectReservedAttributeForgery() error = %v", err)
	}
}

func TestRunGoTestsTerminatesOnContextDeadline(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/timeout\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "timeout_test.go"), []byte(`package timeout

import (
	"testing"
	"time"
)

func TestHang(t *testing.T) { time.Sleep(time.Minute) }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := syntheticCandidates()[0]
	candidate.PackagePath = "."
	candidate.Selector = "timeout_test.go::TestHang"
	candidate.SourcePath = "timeout_test.go"
	candidate.TestName = "TestHang"
	ledger, err := newEventLedger([]app.CommandCoverageOracleCandidate{candidate}, map[string]string{".": "example.test/timeout"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = runGoTests(ctx, root, []ExecutionCommand{{
		Argv:        []string{"go", "test", "-json", "-count=1", "-run", "^TestHang$", "."},
		PackagePath: ".",
	}}, ledger)
	if DecisionID(err) != "process.timeout" {
		t.Fatalf("runGoTests() error = %v, want process.timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("runGoTests() termination took %s", elapsed)
	}
}

func TestRunGoTestCommandTerminatesImmediatelyWhenStderrExceedsBound(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\n/bin/dd if=/dev/zero bs=1048577 count=1 1>&2\n/bin/sleep 5\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err := runGoTestCommand(ctx, t.TempDir(), []string{"go", "test"}, nil)
	if DecisionID(err) != "process.stderr_exceeded" {
		t.Fatalf("runGoTestCommand() error = %v, want process.stderr_exceeded", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("overflow rejection waited for caller cancellation: %v", ctx.Err())
	}
}

func TestRunGoTestCommandStderrCompletion(t *testing.T) {
	writeStderr := func(size int) string {
		return fmt.Sprintf("/bin/dd if=/dev/zero bs=%d count=1 1>&2 2>/dev/null\n", size)
	}
	for _, test := range []struct {
		name     string
		body     string
		decision string
		timeout  time.Duration
	}{
		{name: "empty", body: ":\n"},
		{name: "exact_bound", body: writeStderr(maxStderrBytes)},
		{name: "bound_plus_one", body: writeStderr(maxStderrBytes + 1), decision: "process.stderr_exceeded"},
		{name: "late_exact_bound", body: "exec 1>&-\n/bin/sleep 0.1\n" + writeStderr(maxStderrBytes)},
		{name: "late_bound_plus_one", body: "exec 1>&-\n/bin/sleep 0.1\n" + writeStderr(maxStderrBytes+1), decision: "process.stderr_exceeded"},
		{
			name: "inherited_exact_bound",
			body: "exec 1>&-\n( /bin/sleep 0.2\n" + writeStderr(maxStderrBytes) + ": > stderr-complete\n) &\nexit 0\n",
		},
		{
			name:     "inherited_bound_plus_one",
			body:     "exec 1>&-\n( /bin/sleep 0.2\n" + writeStderr(maxStderrBytes+1) + ") &\nexit 0\n",
			decision: "process.stderr_exceeded",
		},
		{
			name:     "overflow_while_waiting",
			body:     "exec 1>&-\n" + writeStderr(maxStderrBytes+1) + "exec /bin/sleep 5\n",
			decision: "process.stderr_exceeded",
		},
		{
			name:     "timeout_while_waiting",
			body:     "exec 1>&-\nexec /bin/sleep 5\n",
			decision: "process.timeout",
			timeout:  250 * time.Millisecond,
		},
		{
			name:     "stderr_eof_before_parent_exit",
			body:     "exec 1>&-\nexec 2>&-\nexec /bin/sleep 5\n",
			decision: "process.timeout",
			timeout:  250 * time.Millisecond,
		},
		{
			name:     "inherited_timeout_while_waiting",
			body:     "exec 1>&-\n( exec /bin/sleep 5 ) &\nexit 0\n",
			decision: "process.timeout",
			timeout:  250 * time.Millisecond,
		},
		{name: "exit_failure", body: "printf 'private stderr sentinel' >&2\nexit 7\n", decision: "process.suite_failed"},
		{name: "malformed_stdout", body: "printf 'not-json\\n'\n/bin/sleep 5\n", decision: "event.json_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			prefix, ledger := passingCommandScript(t)
			path := filepath.Join(root, "command")
			if err := os.WriteFile(path, []byte(prefix+test.body), 0o700); err != nil {
				t.Fatal(err)
			}
			timeout := test.timeout
			if timeout == 0 {
				timeout = 3 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			err := runGoTestCommand(ctx, root, []string{path}, ledger)
			if test.decision == "" && err != nil || test.decision != "" && DecisionID(err) != test.decision {
				t.Fatalf("runGoTestCommand() error = %v, want %q", err, test.decision)
			}
			if err != nil && strings.Contains(err.Error(), "private stderr sentinel") {
				t.Fatalf("runGoTestCommand() disclosed child stderr: %v", err)
			}
			if test.decision == "process.timeout" && ctx.Err() == nil {
				t.Fatal("timeout decision without caller cancellation")
			}
			if test.decision != "process.timeout" && ctx.Err() != nil {
				t.Fatalf("caller context expired before completion: %v", ctx.Err())
			}
			if test.name == "inherited_exact_bound" {
				if _, err := os.Stat(filepath.Join(root, "stderr-complete")); err != nil {
					t.Fatalf("command returned before inherited stderr completed: %v", err)
				}
			}
			if err := ledger.finalize(); err != nil {
				t.Fatalf("valid stdout event ledger did not close: %v", err)
			}
		})
	}
}

func TestRunGoTestCommandRejectsHeldStderrWaitDelay(t *testing.T) {
	fixture := startHeldStderrCommand(t, "exit 0\n", nil)
	// The test owns the extra writer until cleanup, independently of parent exit.
	err := fixture.join(t)
	if DecisionID(err) != "process.suite_failed" {
		t.Fatalf("held stderr error = %v, want process.suite_failed", err)
	}
	if fixture.ctx.Err() != nil || !fixture.stderr.expired {
		t.Fatalf("drain deadline not independent of context: expired=%v context=%v", fixture.stderr.expired, fixture.ctx.Err())
	}
	if fixture.stderr.done != nil || !fixture.stderr.closed {
		t.Fatal("deadline returned without closing and joining stderr")
	}
}

func TestRunGoTestCommandHeldStderrAbort(t *testing.T) {
	for _, test := range []struct {
		name     string
		body     string
		overflow bool
		cancel   bool
		decision string
	}{
		{name: "parser", body: "printf 'not-json\\n'\nexec /bin/sleep 5\n", decision: "event.json_invalid"},
		{name: "overflow_parser_pending", body: "exec /bin/sleep 5\n", overflow: true, decision: "process.stderr_exceeded"},
		{name: "overflow_stdout_closed", body: "exec 1>&-\nexec /bin/sleep 5\n", overflow: true, decision: "process.stderr_exceeded"},
		{name: "context_parser_pending", body: "exec /bin/sleep 5\n", cancel: true, decision: "process.timeout"},
		{name: "context_stdout_closed", body: "exec 1>&-\nexec /bin/sleep 5\n", cancel: true, decision: "process.timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := startHeldStderrCommand(t, test.body, nil)
			if test.overflow {
				if _, err := fixture.writer.Write(bytes.Repeat([]byte{'x'}, maxStderrBytes+1)); err != nil {
					t.Fatal(err)
				}
			}
			if test.cancel {
				fixture.cancel()
			}
			// No release/Close of the test-owned writer precedes this join.
			err := fixture.join(t)
			if DecisionID(err) != test.decision {
				t.Fatalf("held-writer result = %v, want %s", err, test.decision)
			}
			if (fixture.ctx.Err() != nil) != test.cancel {
				t.Fatalf("unexpected caller cancellation: %v", fixture.ctx.Err())
			}
			if !fixture.stderr.aborted || fixture.stderr.done != nil || !fixture.stderr.closed {
				t.Fatal("failure did not abort and join its owned stderr")
			}
		})
	}
}

func TestRunGoTestCommandHeldStderrCompletion(t *testing.T) {
	for _, size := range []int{0, maxStderrBytes, maxStderrBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			fixture := startHeldStderrCommand(t, "exit 0\n", nil)
			if _, err := fixture.writer.Write(bytes.Repeat([]byte{'x'}, size)); err != nil {
				t.Fatal(err)
			}
			if err := fixture.writer.Close(); err != nil {
				t.Fatal(err)
			}
			err := fixture.join(t)
			if size <= maxStderrBytes && err != nil || size > maxStderrBytes && DecisionID(err) != "process.stderr_exceeded" {
				t.Fatalf("size %d result = %v", size, err)
			}
			if fixture.ctx.Err() != nil {
				t.Fatal(fixture.ctx.Err())
			}
			if size > maxStderrBytes && !fixture.stderr.aborted {
				t.Fatal("completion discarded the overflow termination transition")
			}
		})
	}
}

func TestRunGoTestCommandRetainsSanitizedStderrFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		read     bool
		body     string
		decision string
	}{
		{name: "copy", read: true, body: "exit 0\n", decision: "process.suite_failed"},
		{name: "close", body: "exit 0\n", decision: "process.suite_failed"},
		{name: "parser_with_close", body: "printf 'not-json\\n'\nexec /bin/sleep 5\n", decision: "event.json_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := startHeldStderrCommand(t, test.body, func(reader io.ReadCloser) io.ReadCloser {
				return &faultingStderrReader{ReadCloser: reader, readFailure: test.read, closeFailure: !test.read}
			})
			if err := fixture.writer.Close(); err != nil {
				t.Fatal(err)
			}
			err := fixture.join(t)
			failure := "close failed"
			if test.read {
				failure = "copy failed"
			}
			if DecisionID(err) != test.decision || !strings.Contains(err.Error(), failure) {
				t.Fatalf("lost %s failure: %v", test.name, err)
			}
			if strings.Contains(err.Error(), "private stderr sentinel") {
				t.Fatalf("disclosed raw failure: %v", err)
			}
			if fixture.ctx.Err() != nil {
				t.Fatal(fixture.ctx.Err())
			}
		})
	}
}

func TestRunGoTestCommandStartFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command")
	if err := os.WriteFile(path, []byte("#!/nonexistent-command-oracle-interpreter\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := runGoTestCommand(t.Context(), t.TempDir(), []string{path}, nil)
	if DecisionID(err) != "process.start_failed" {
		t.Fatalf("start failure = %v", err)
	}
}

func TestHeldStderrCommandCleanupJoinsUnreleasedFixture(t *testing.T) {
	var fixture *heldStderrCommand
	t.Run("cleanup_without_explicit_join", func(t *testing.T) {
		fixture = startHeldStderrCommand(t, "exec /bin/sleep 5\n", nil)
	})
	if fixture == nil || !fixture.joined || fixture.stderr.done != nil || !fixture.stderr.closed {
		t.Fatal("fixture cleanup did not release and join the sole Wait owner")
	}
}

type faultingStderrReader struct {
	io.ReadCloser
	readFailure  bool
	closeFailure bool
}

func (reader *faultingStderrReader) Read(value []byte) (int, error) {
	if reader.readFailure {
		return 0, errors.New("private stderr sentinel")
	}
	return reader.ReadCloser.Read(value)
}

func (reader *faultingStderrReader) Close() error {
	err := reader.ReadCloser.Close()
	if reader.closeFailure {
		return errors.New("private stderr sentinel")
	}
	return err
}

type heldStderrCommand struct {
	ctx    context.Context
	cancel context.CancelFunc
	writer *os.File
	stderr *commandStderr
	done   chan error
	joined bool
}

func startHeldStderrCommand(t *testing.T, body string, wrap func(io.ReadCloser) io.ReadCloser) *heldStderrCommand {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), processWaitDelay+5*time.Second)
	fixture := &heldStderrCommand{ctx: ctx, cancel: cancel, writer: writer}
	// Register before Start/assertions. Only waitGoTestCommand calls Cmd.Wait.
	t.Cleanup(func() {
		cancel()
		if err := writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
		if fixture.done == nil {
			_ = reader.Close()
		} else if !fixture.joined {
			select {
			case <-fixture.done:
				fixture.joined = true
			case <-time.After(5 * time.Second):
				t.Error("owned command cleanup did not join")
			}
		}
	})
	prefix, ledger := passingCommandScript(t)
	command := exec.CommandContext(ctx, "/bin/sh", "-c", prefix+body)
	command.WaitDelay = processWaitDelay
	processgroup.Configure(command)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = writer
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var stderrReader io.ReadCloser = reader
	if wrap != nil {
		stderrReader = wrap(stderrReader)
	}
	fixture.stderr = startCommandStderr(stderrReader)
	fixture.done = make(chan error, 1)
	go func() {
		fixture.done <- waitGoTestCommand(ctx, command, stdout, fixture.stderr, ledger, nil, func() error {
			return processgroup.Terminate(command)
		})
	}()
	return fixture
}

func (fixture *heldStderrCommand) join(t *testing.T) error {
	t.Helper()
	select {
	case err := <-fixture.done:
		fixture.joined = true
		return err
	case <-fixture.ctx.Done():
		// Cancellation cases still need the actual runner result and join.
		select {
		case err := <-fixture.done:
			fixture.joined = true
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("owned command did not complete after cancellation")
			return nil
		}
	}
}

func TestCommandStderrCompletionAndDeadlineOrdering(t *testing.T) {
	for _, test := range []struct {
		name  string
		abort bool
	}{
		{name: "completion_before_deadline"},
		{name: "completion_queued_at_deadline"},
		{name: "nil_completion_after_abort", abort: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			drain := startCommandStderr(reader)
			t.Cleanup(func() {
				_ = writer.Close()
				drain.abort()
				if drain.done != nil {
					drain.receive(<-drain.done)
				}
			})
			drain.parentWaited()
			if drain.deadline == nil || drain.failure() == nil {
				t.Fatal("pending observation was accepted or left unbounded")
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			copyErr := <-drain.done
			// Keep the joined result available even if an assertion fails below.
			drain.done <- copyErr
			if copyErr != nil {
				t.Fatal(copyErr)
			}
			if test.abort {
				drain.abort()
			}
			if test.name == "completion_queued_at_deadline" {
				drain.expire()
			} else {
				drain.receive(<-drain.done)
				drain.expire() // A stale timer must not change accepted completion.
			}
			drain.close()
			if drain.done != nil || drain.deadline != nil || drain.expired {
				t.Fatal("completion left pending state or accepted a stale deadline")
			}
			if (drain.failure() != nil) != test.abort {
				t.Fatalf("completion/abort classification = %v", drain.failure())
			}
		})
	}
}

func TestCommandStderrUnexpectedClosedReaderIsNotSuccess(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	drain := startCommandStderr(reader)
	// No abort was admitted before this close.
	drain.close()
	drain.receive(<-drain.done)
	if drain.copyErr == nil || drain.failure() == nil {
		t.Fatal("unexpected closed reader became a complete observation")
	}
}

func TestWaitGoTestCommandExpiredOverflowTerminatesOnce(t *testing.T) {
	for _, test := range []struct {
		name         string
		lateNil      bool
		malformed    bool
		terminateErr bool
	}{
		{name: "closed_copy"},
		{name: "late_nil", lateNil: true},
		{name: "second_abort_reason", lateNil: true, malformed: true},
		{name: "failed_termination_is_not_retried", lateNil: true, malformed: true, terminateErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			reader, writer, err := os.Pipe()
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			release := make(chan struct{})
			var once sync.Once
			releaseCopy := func() { once.Do(func() { close(release) }) }
			body := "exit 0"
			if test.malformed {
				body = "printf 'not-json\\n'"
			}
			command := exec.CommandContext(ctx, "/bin/sh", "-c", body)
			started, waitOwned := false, false
			var stderr *commandStderr
			t.Cleanup(func() {
				cancel()
				releaseCopy()
				_ = writer.Close()
				if stderr == nil {
					_ = reader.Close()
				} else {
					stderr.abort()
					if stderr.done != nil {
						stderr.receive(<-stderr.done)
					}
				}
				if started && !waitOwned {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			})
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			command.Stderr = writer
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			started = true
			stderr = startCommandStderr(&heldCopyResultReader{ReadCloser: reader, release: release, lateNil: test.lateNil})
			if _, err := writer.Write(bytes.Repeat([]byte{'x'}, maxStderrBytes+1)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-stderr.bounded.Exceeded():
			case <-ctx.Done():
				t.Fatal("stderr did not observe overflow")
			}
			// Model the timer-winning select prefix with real observed overflow and
			// copy completion held back. No scheduler timing is needed for this edge.
			stderr.expire()
			if !stderr.expired || !stderr.aborted || stderr.done == nil {
				t.Fatal("expiry did not establish the pending-copy transition")
			}
			terminationCalls := 0
			waitOwned = true
			err = waitGoTestCommand(ctx, command, &releasingStdoutReader{ReadCloser: stdout, release: releaseCopy}, stderr, nil, nil, func() error {
				terminationCalls++
				if test.terminateErr {
					return errors.New("private termination sentinel")
				}
				return nil
			})
			if terminationCalls != 1 {
				t.Errorf("local termination calls = %d, want exactly one after stream expiry", terminationCalls)
			}
			if DecisionID(err) != "process.stderr_exceeded" || stderr.failure() == nil {
				t.Errorf("expired/overflow observation became successful: %v", err)
			}
			if stderr.done != nil || ctx.Err() != nil {
				t.Errorf("copy not joined or caller expired: pending=%v context=%v", stderr.done != nil, ctx.Err())
			}
			if test.lateNil && stderr.copyErr != nil {
				t.Errorf("late nil completion was not exercised: %v", stderr.copyErr)
			}
			if test.terminateErr && !strings.Contains(err.Error(), "process termination failed") {
				t.Errorf("termination failure lost: %v", err)
			}
			if strings.Contains(err.Error(), "private termination sentinel") {
				t.Errorf("raw termination error escaped: %v", err)
			}
		})
	}
}

type heldCopyResultReader struct {
	io.ReadCloser
	release <-chan struct{}
	lateNil bool
}

func (reader *heldCopyResultReader) Read(value []byte) (int, error) {
	count, err := reader.ReadCloser.Read(value)
	if err != nil {
		<-reader.release
		if reader.lateNil {
			err = io.EOF
		}
	}
	return count, err
}

type releasingStdoutReader struct {
	io.ReadCloser
	release func()
}

func (reader *releasingStdoutReader) Close() error {
	err := reader.ReadCloser.Close()
	reader.release()
	return err
}

func passingCommandScript(t *testing.T) (string, *eventLedger) {
	t.Helper()
	candidate := syntheticCandidates()[0]
	const packageImport = "example.test/stderr"
	ledger, err := newEventLedger([]app.CommandCoverageOracleCandidate{candidate}, map[string]string{candidate.PackagePath: packageImport})
	if err != nil {
		t.Fatal(err)
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\nset -eu\n/bin/cat <<'EVENTS'\n")
	encoder := json.NewEncoder(&script)
	for _, event := range []testEvent{
		{Action: "start", Package: packageImport},
		{Action: "run", Package: packageImport, Test: candidate.TestName},
		{Action: "attr", Package: packageImport, Test: candidate.TestName, Key: commandcoverage.ExecutionAttributeKey, Value: candidate.SourceMarker},
		{Action: "pass", Package: packageImport, Test: candidate.TestName},
		{Action: "pass", Package: packageImport},
	} {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	script.WriteString("EVENTS\n")
	return script.String(), ledger
}

func TestExecutionCommandsKeepPackageTestSetsDisjoint(t *testing.T) {
	candidates := syntheticCandidates()
	candidates[0].PackagePath = "./internal/one"
	candidates[0].TestName = "TestOne"
	candidates[1].PackagePath = "./internal/two"
	candidates[1].TestName = "TestTwo"

	commands := executionCommands(candidates)
	if len(commands) != 2 {
		t.Fatalf("executionCommands() count = %d, want 2", len(commands))
	}
	if got := commands[0].Argv[len(commands[0].Argv)-2:]; !slices.Equal(got, []string{"^(TestOne)$", "./internal/one"}) {
		t.Fatalf("first package command = %#v", commands[0].Argv)
	}
	if got := commands[1].Argv[len(commands[1].Argv)-2:]; !slices.Equal(got, []string{"^(TestTwo)$", "./internal/two"}) {
		t.Fatalf("second package command = %#v", commands[1].Argv)
	}
}

func TestRunGoTestsDoesNotExecuteCrossPackageNameMatches(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/exact\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writePackage := func(directory string, selectedName string, selectedMarker string, forbiddenName string) {
		t.Helper()
		path := filepath.Join(root, directory)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		source := "package " + directory + `

import "testing"

func ` + selectedName + `(t *testing.T) {
	t.Attr("proofkit.command-oracle", "` + selectedMarker + `")
}

func ` + forbiddenName + `(t *testing.T) {
	t.Fatal("cross-package selector executed a non-candidate test")
}
`
		if err := os.WriteFile(filepath.Join(path, directory+"_test.go"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidates := syntheticCandidates()
	candidates[0].PackagePath = "./one"
	candidates[0].Selector = "one/one_test.go::TestOne"
	candidates[0].SourcePath = "one/one_test.go"
	candidates[0].TestName = "TestOne"
	candidates[1].PackagePath = "./two"
	candidates[1].Selector = "two/two_test.go::TestTwo"
	candidates[1].SourcePath = "two/two_test.go"
	candidates[1].TestName = "TestTwo"
	writePackage("one", "TestOne", candidates[0].SourceMarker, "TestTwo")
	writePackage("two", "TestTwo", candidates[1].SourceMarker, "TestOne")
	imports := map[string]string{
		"./one": "example.test/exact/one",
		"./two": "example.test/exact/two",
	}
	ledger, err := newEventLedger(candidates, imports)
	if err != nil {
		t.Fatal(err)
	}
	if err := runGoTests(context.Background(), root, executionCommands(candidates), ledger); err != nil {
		t.Fatalf("runGoTests() error = %v", err)
	}
	if err := ledger.finalize(); err != nil {
		t.Fatalf("event ledger did not close: %v", err)
	}
}
