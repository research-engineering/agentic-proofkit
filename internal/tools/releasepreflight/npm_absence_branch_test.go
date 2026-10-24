package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/childcoverage"
	"go.yaml.in/yaml/v3"
)

// Only the isolated Bash witness invokes this subprocess-only entrypoint.
// Calling main preserves real dispatch, diagnostics and exit status, without
// building or invoking Go, npm or Node inside the shell. Do not bind this helper.
func TestNPMAbsenceBranchEntrypoint(t *testing.T) {
	if os.Getenv("PROOFKIT_BRANCH_ENTRYPOINT") != "1" {
		return
	}
	index := slices.Index(os.Args, "--")
	if index < 0 || len(os.Args[index+1:]) != 3 || os.Args[index+1] != "npm-absent" || os.Args[index+2] != "--error-file" {
		os.Exit(97)
	}
	var ready *os.File
	if os.Getenv("PROOFKIT_BRANCH_READY") == "1" {
		ready = os.NewFile(3, "classifier-readiness")
		if ready == nil {
			os.Exit(97)
		}
		// Keep this descriptor until os.Exit; EOF is the independent exit witness.
		if _, err := ready.Write([]byte{1}); err != nil {
			os.Exit(97)
		}
		// The inherited reader exists before readiness; no later path open can
		// lose a permit sent while this entrypoint is descheduled.
		release := os.NewFile(6, "classifier-release")
		if release == nil {
			os.Exit(97)
		}
		if err := npmBranchMarker(release, 1); err != nil {
			os.Exit(97)
		}
		if err := release.Close(); err != nil {
			os.Exit(97)
		}
	}
	os.Args = append([]string{"releasepreflight"}, os.Args[index+1:]...)
	main()
	if ready != nil {
		if _, err := ready.Write([]byte{2}); err != nil {
			os.Exit(97)
		}
	}
	os.Exit(0)
}

type npmBranchCase struct {
	name, payload, stderr  string
	viewExit, existingExit int
	publish, success       bool
	wantLimit              string
	delayedChildStartup    bool
	lateReadyObservation   bool
	pendingSignalAtBlock   bool
	removeCleanupWait      bool
}

func testNPMAbsenceBranchExecution(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("extraction boundaries", func(t *testing.T) {
		step := []byte("      - name: Build publish dry-run evidence\n")
		if bytes.Count(raw, step) != 1 || bytes.Count(raw, []byte("jobs:\n")) != 1 {
			t.Fatal("extraction counterexample target drift")
		}
		for _, item := range []struct {
			name, want string
			raw        []byte
		}{
			{"duplicate job", "invalid branch witness workflow", bytes.Replace(raw, []byte("jobs:\n"), []byte("jobs:\n  candidate: {}\n"), 1)},
			{"duplicate step", "branch witness requires exactly one named job step", bytes.Replace(raw, step, append(append(bytes.Clone(step), []byte("        run: 'true'\n")...), step...), 1)},
			{"missing step", "branch witness requires exactly one named job step", bytes.Replace(raw, step, []byte("      - name: unrelated\n"), 1)},
			{"extra document", "branch witness requires exactly one YAML document", append(bytes.Clone(raw), []byte("\n---\n{}\n")...)},
			{"missing header", "branch witness header or boundary order drift", bytes.ReplaceAll(raw, []byte("set -euo pipefail\n"), []byte("true\n"))},
			{"duplicate boundary", "branch witness requires unique extraction boundaries", bytes.ReplaceAll(raw, []byte("          mkdir -p artifacts/publish\n"), []byte("          mkdir -p artifacts/publish\n          mkdir -p artifacts/publish\n"))},
		} {
			t.Run(item.name, func(t *testing.T) {
				if _, _, err := npmAbsenceBranchFragment(item.raw, "candidate"); err == nil || err.Error() != item.want {
					t.Fatalf("extraction rejection=%v, want %q", err, item.want)
				}
			})
		}
	})
	cases := []npmBranchCase{
		{name: "E404", payload: `{"error":{"code":"E404"}}`, viewExit: 1, publish: true, success: true},
		{name: "E403", payload: `{"error":{"code":"E403","summary":"Not found"}}`, viewExit: 1, stderr: "npm view error code is not E404\n"},
		{name: "E500", payload: `{"error":{"code":"E500","summary":"Not found"}}`, viewExit: 1, stderr: "npm view error code is not E404\n"},
		{name: "empty", viewExit: 1, stderr: "invalid npm view error report\n"},
		{name: "trailing", payload: `{"error":{"code":"E404"}}{}`, viewExit: 1, stderr: "invalid npm view error report\n"},
		{name: "existing byte match", payload: `[]`, success: true},
		{name: "existing byte mismatch", payload: `[]`, existingExit: 1, stderr: "fixture existing byte mismatch\n"},
	}
	for _, job := range []string{"candidate", "publish"} {
		t.Run(job+"/omitted setup changes shell policy", func(t *testing.T) {
			marker := "      - name: Build publish dry-run evidence\n        run: |\n          set -euo pipefail\n          mkdir -p artifacts/publish\n"
			if job == "publish" {
				marker = "      - name: Publish to npm\n        run: |\n          set -euo pipefail\n          mkdir -p artifacts/registry\n"
			}
			if bytes.Count(raw, []byte(marker)) != 1 {
				t.Fatal("omitted setup mutation target drift")
			}
			mutated := bytes.Replace(raw, []byte(marker), []byte(marker+"          set +e\n"), 1)
			if _, _, err := npmAbsenceBranchFragment(mutated, job); err == nil || err.Error() != "branch witness omitted setup changed; requalify shell context" {
				t.Fatalf("changed omitted context admitted: %v", err)
			}
		})
	}
	for _, job := range []string{"candidate", "publish"} {
		header, body, err := npmAbsenceBranchFragment(raw, job)
		if err != nil {
			t.Fatal(err)
		}
		if job == "candidate" {
			t.Run("carrier/dispatch permit queued before read", func(t *testing.T) {
				control := newNPMBranchControl(t)
				if err := control.release(); err != nil {
					t.Fatal(err)
				}
				if err := npmBranchMarker(control.releaseReader, 1); err != nil {
					t.Fatalf("queued dispatch permit was lost: %v", err)
				}
				if n, err := control.releaseReader.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatalf("dispatch writer did not close after one permit: n=%d err=%v", n, err)
				}
			})
			t.Run("carrier/signal precedes its pipe close", func(t *testing.T) {
				// The signal sender observes the pipe: a close before the signal is
				// refused on every run, not only when Bash happens to read EOF first.
				control := newNPMBranchControl(t)
				sent := errors.New("fixture signal result")
				atSignal := errors.New("signal sender not called")
				err := control.signalCarrier(func() error {
					atSignal = npmBranchSignalPipeOpen(control.signalReader)
					return sent
				})
				if atSignal != nil {
					t.Fatalf("signal-sent pipe at the signal: %v", atSignal)
				}
				if !errors.Is(err, sent) {
					t.Fatalf("cancellation result=%v, want the signal sender's result", err)
				}
				if n, err := control.signalReader.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatalf("signal-sent pipe did not close after the signal: n=%d err=%v", n, err)
				}
			})
			t.Run("carrier/stdio bound", func(t *testing.T) {
				item := cases[0]
				item.wantLimit = "stdio"
				executeNPMAbsenceBranch(t, header+"printf '%17000s' x\n", body, item)
			})
			pendingSignal := "signal pending when the carrier blocks"
			for _, startup := range []struct {
				name                 string
				delayedChildStartup  bool
				lateReadyObservation bool
				pendingSignalAtBlock bool
			}{
				{name: "immediate"},
				{name: "delayed child startup", delayedChildStartup: true},
				{name: "delayed readiness observation", lateReadyObservation: true},
				{name: pendingSignal, pendingSignalAtBlock: true},
			} {
				t.Run("carrier/blocked entrypoint cancellation/"+startup.name, func(t *testing.T) {
					item := cases[0]
					item.wantLimit = "context"
					item.delayedChildStartup = startup.delayedChildStartup
					item.lateReadyObservation = startup.lateReadyObservation
					item.pendingSignalAtBlock = startup.pendingSignalAtBlock
					result := executeNPMAbsenceBranch(t, header, body, item)
					if result.orderingError != nil {
						t.Fatal(result.orderingError)
					}
					if result.trace != "view\nabsent\ncancelled\nreaped\n" {
						t.Fatalf("cancelled carrier must reap the classifier before shell exit: trace=%q exit=%d", result.trace, result.exitCode)
					}
				})
			}
			for _, schedule := range []string{"immediate", pendingSignal} {
				t.Run("carrier/removed cleanup wait counterexample/"+schedule, func(t *testing.T) {
					item := cases[0]
					item.wantLimit = "context"
					item.removeCleanupWait = true
					item.pendingSignalAtBlock = schedule == pendingSignal
					result := executeNPMAbsenceBranch(t, header, body, item)
					if result.orderingError == nil || result.orderingError.Error() != "carrier cleanup did not wait for classifier exit" {
						t.Fatalf("removed-wait rejection=%v, want live-classifier cause", result.orderingError)
					}
					if result.trace != "view\nabsent\ncancelled\nreaped\n" || result.exitCode != 124 {
						t.Fatalf("removed-wait mutant changed protected trace or exit: trace=%q exit=%d", result.trace, result.exitCode)
					}
				})
			}
		}
		for _, item := range cases {
			t.Run(job+"/"+item.name, func(t *testing.T) {
				result := executeNPMAbsenceBranch(t, header, body, item)
				if err := checkNPMAbsenceBranch(result, item, job); err != nil {
					t.Fatal(err)
				}
			})
		}
		t.Run(job+"/set +e counterexample", func(t *testing.T) {
			step := "Build publish dry-run evidence"
			if job == "publish" {
				step = "Publish to npm"
			}
			marker := []byte("      - name: " + step + "\n        run: |\n          set -euo pipefail\n")
			if bytes.Count(raw, marker) != 1 {
				t.Fatal("counterexample requires one exact named step header")
			}
			mutated := bytes.Replace(raw, marker, append(bytes.Clone(marker), []byte("          set +e\n")...), 1)
			mutantHeader, mutantBody, err := npmAbsenceBranchFragment(mutated, job)
			if err != nil {
				t.Fatalf("counterexample must reach execution: %v", err)
			}
			if mutantBody != body || mutantHeader != strings.Replace(header, "set -euo pipefail\n", "set -euo pipefail\nset +e\n", 1) {
				t.Fatal("counterexample changed more than the selected shell header")
			}
			result := executeNPMAbsenceBranch(t, mutantHeader, mutantBody, cases[1])
			if result.exitCode != 0 || result.stderr != cases[1].stderr || result.trace != "view\nabsent\nreaped\npublish\ncomplete\n" {
				t.Fatal("counterexample did not preserve classifier rejection and reach mocked publish")
			}
			if err := checkNPMAbsenceBranch(result, cases[1], job); err == nil || err.Error() != "rejected npm view reached publish" {
				t.Fatalf("counterexample rejection=%v, want publication-after-rejection cause", err)
			}
		})
	}
}

func npmAbsenceBranchFragment(raw []byte, job string) (string, string, error) {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&workflow); err != nil {
		return "", "", fmt.Errorf("invalid branch witness workflow")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", "", fmt.Errorf("branch witness requires exactly one YAML document")
	}
	step, headerEnd, path, endMarker := "Build publish dry-run evidence", "mkdir -p artifacts/publish\n", "/tmp/proofkit-candidate-view", "\n  npm view \"${package_name}@latest\""
	if job == "publish" {
		step, headerEnd, path, endMarker = "Publish to npm", "mkdir -p artifacts/registry\n", "/tmp/proofkit-npm-view", "\n  echo \"$filename\" >> artifacts/registry/npm-published-filenames.txt"
	} else if job != "candidate" {
		return "", "", fmt.Errorf("unknown branch witness job")
	}
	var runs []string
	for _, candidate := range workflow.Jobs[job].Steps {
		if candidate.Name == step {
			runs = append(runs, candidate.Run)
		}
	}
	if len(runs) != 1 {
		return "", "", fmt.Errorf("branch witness requires exactly one named job step")
	}
	run := runs[0]
	startMarker := "  if npm view \"${package_name}@${package_version}\" name version dist --json --registry=\"${REGISTRY_URL}\" >" + path + ".json 2>" + path + ".err; then\n"
	loopStart, loopEnd := "while IFS= read -r filename; do\n", "done < artifacts/publish/publish-order.txt\n"
	for _, marker := range []string{headerEnd, startMarker, endMarker, loopStart, loopEnd} {
		if strings.Count(run, marker) != 1 {
			return "", "", fmt.Errorf("branch witness requires unique extraction boundaries")
		}
	}
	h, start, end := strings.Index(run, headerEnd), strings.Index(run, startMarker), strings.Index(run, endMarker)
	if !strings.HasPrefix(run, "set -euo pipefail\n") || h <= 0 || h >= strings.Index(run, loopStart) || strings.Index(run, loopStart) >= start || start >= end || end >= strings.Index(run, loopEnd) {
		return "", "", fmt.Errorf("branch witness header or boundary order drift")
	}
	// The nonexecuted setup may affect shell options and loop context. Changes
	// require requalification instead of silently inheriting the branch proof.
	expectedSetup := map[string]string{
		"candidate": "a8d1ee67b758183ddc848fda88e8d11f81d9dd109f4535ea024cbdd1224e9941",
		"publish":   "ab41fc4621d336f0ed75d271bae7c2aeecaa040944de2d715d3b551c18fcee67",
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(run[h:start]))) != expectedSetup[job] {
		return "", "", fmt.Errorf("branch witness omitted setup changed; requalify shell context")
	}
	body := run[start:end]
	if strings.Count(body, path+".json") != 3 || strings.Count(body, path+".err") != 1 {
		return "", "", fmt.Errorf("branch witness temporary file wiring drift")
	}
	// Only isolate the two fixed temporary paths; execute the actual branch bytes.
	body = strings.ReplaceAll(body, path+".json", "./npm-view.json")
	body = strings.ReplaceAll(body, path+".err", "./npm-view.err")
	return run[:h], body, nil
}

type npmBranchResult struct {
	trace, stdout, stderr string
	exitCode              int
	orderingError         error
}

func checkNPMAbsenceBranch(result npmBranchResult, item npmBranchCase, job string) error {
	wantTrace, wantStderr := "view\n", item.stderr
	if item.viewExit != 0 {
		wantTrace += "absent\nreaped\n"
	} else {
		wantTrace += "existing\n"
		if item.success && job == "candidate" {
			wantTrace += "node\n"
		}
		if item.success && job == "publish" {
			wantStderr = "fixture@1.2.3 already exists and matches the candidate artifact; skipping publish\n"
		}
	}
	if result.stdout != "" || result.stderr != wantStderr {
		return fmt.Errorf("branch output differs from exact safe cause")
	}
	if !item.publish && strings.Contains(result.trace, "publish\n") {
		return fmt.Errorf("rejected npm view reached publish")
	}
	if item.publish {
		wantTrace += "publish\n"
	}
	wantExit := 1
	if item.success {
		wantTrace += "complete\n"
		wantExit = 0
	}
	if result.trace != wantTrace || result.exitCode != wantExit {
		return fmt.Errorf("branch exit or exact event trace differs from expected outcome")
	}
	return nil
}

// This bounded carrier exists only for the two npm workflow fragments above.
func executeNPMAbsenceBranch(t *testing.T, header, body string, item npmBranchCase) npmBranchResult {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "artifacts", "registry"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const childTimeout = 3 * time.Second
	var control *npmBranchControl
	if item.wantLimit == "context" {
		// Hold the test entrypoint before real dispatch, then release it only
		// after cancellation. The deadline bounds faults; it is not the oracle.
		control = newNPMBranchControl(t)
	}
	// Cancellation is one SIGTERM after Bash reports P. Bash 3.2 handles a trapped
	// signal that arrives after its last pending-trap check before wait only when the
	// awaited child exits, and the held classifier exits only at its own
	// -test.timeout; one that arrives while wait sets up its interruption crashes
	// Bash 3.2. The controlled shim therefore blocks on descriptor 7 instead,
	// which signalCarrier closes only after the signal was sent, so the trap runs
	// while the classifier is still held, whenever the signal arrives. pendingSignalAtBlock
	// sends the signal after Bash's last pending-trap check before that read.
	// The uncontrolled shim keeps waiting for the classifier it started.
	script := `child=
cleanup() {
  if [[ -n "$child" ]]; then
    if [[ "$BRANCH_CONTROL" == 1 ]]; then printf W >&5; fi
    wait "$child" 2>/dev/null || :
    if [[ "$BRANCH_CONTROL" == 1 ]]; then
      printf D >&5
      IFS= read -r permit <&4
      [[ "$permit" == finish ]] || return 97
    fi
    printf 'reaped\n' >> trace
    child=
  fi
}
trap cleanup EXIT
trap 'printf "cancelled\n" >> trace; if [[ "$BRANCH_CONTROL" == 1 ]]; then printf C >&5; fi; exit 124' TERM INT
npm() {
  case "$1" in
    view) printf 'view\n' >> trace; printf '%s' "$BRANCH_PAYLOAD"; printf 'E404 Not found diagnostic-marker\n' >&2; return "$BRANCH_VIEW_EXIT" ;;
    publish) printf 'publish\n' >> trace ;;
    *) return 97 ;;
  esac
}
go() {
  [[ "$1" == run && "$2" == ./internal/tools/releasepreflight ]] || return 97
  shift 2
  case "$1" in
    npm-existing)
      printf 'existing\n' >> trace
      if [[ "$BRANCH_EXISTING_EXIT" != 0 ]]; then printf 'fixture existing byte mismatch\n' >&2; fi
      return "$BRANCH_EXISTING_EXIT"
      ;;
    npm-absent)
      printf 'absent\n' >> trace
      if [[ "$BRANCH_DELAY_START" == 1 ]]; then
        printf T >&5
        IFS= read -r permit <&4
        [[ "$permit" == start ]] || return 97
      fi
      "$BRANCH_BINARY" -test.run='^TestNPMAbsenceBranchEntrypoint$' -test.timeout=` + childTimeout.String() + ` -- "$@" </dev/null 4<&- 5>&- 7<&- &
      if [[ "$BRANCH_CONTROL" == 1 ]]; then
        exec 3>&- 6<&-
        printf S >&5
        IFS= read -r permit <&4
        [[ "$permit" == register ]] || return 97
      fi
      child=$!
      if [[ "$BRANCH_CONTROL" == 1 ]]; then
        printf P >&5
        if [[ "$BRANCH_PENDING_SIGNAL" == 1 ]]; then
          IFS= read -r permit <&"$(printf E >&5; IFS= read -r permit <&7 || :; printf 7)" || :
        else
          IFS= read -r permit <&7 || :
        fi
        return 97
      fi
      local status=0
      wait "$child" || status=$?
      child=
      printf 'reaped\n' >> trace
      return "$status"
      ;;
    *) return 97 ;;
  esac
}
node() { printf 'node\n' >> trace; }
package_name=fixture
package_version=1.2.3
REGISTRY_URL=unused
metadata=fixture
report=report.json
` + header + "for filename in fixture.tgz; do\n" + body + "\ndone\nprintf 'complete\\n' >> trace\n"
	if item.removeCleanupWait {
		const wait = "    wait \"$child\" 2>/dev/null || :\n"
		if strings.Count(script, wait) != 1 {
			t.Fatal("cleanup wait mutation target drift")
		}
		script = strings.Replace(script, wait, "    :\n", 1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deadline := time.AfterFunc(5*time.Second, cancel)
	defer deadline.Stop()
	cmd := exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", "-c", script)
	cmd.Dir = dir
	cmd.Env = childcoverage.Environment(t, []string{"PATH=" + dir, "HOME=" + dir, "TMPDIR=" + dir, "PROOFKIT_BRANCH_ENTRYPOINT=1", "BRANCH_BINARY=" + binary, "BRANCH_PAYLOAD=" + item.payload, fmt.Sprintf("BRANCH_VIEW_EXIT=%d", item.viewExit), fmt.Sprintf("BRANCH_EXISTING_EXIT=%d", item.existingExit), "BRANCH_CONTROL=0", "BRANCH_DELAY_START=0", "BRANCH_PENDING_SIGNAL=0"})
	cmd.Cancel = func() error {
		return control.signalCarrier(func() error { return cmd.Process.Signal(syscall.SIGTERM) })
	}
	cmd.WaitDelay = childTimeout + time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if control != nil {
		cmd.ExtraFiles = []*os.File{control.readyWriter, control.commandReader, control.eventWriter, control.releaseReader, control.signalReader}
		cmd.Env = append(cmd.Env, "PROOFKIT_BRANCH_READY=1", "BRANCH_CONTROL=1")
		if item.delayedChildStartup {
			cmd.Env = append(cmd.Env, "BRANCH_DELAY_START=1")
		}
		if item.pendingSignalAtBlock {
			cmd.Env = append(cmd.Env, "BRANCH_PENDING_SIGNAL=1")
		}
	}
	var stdout, stderr npmBranchOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Nil stdin is /dev/null; the sole spawned entrypoint also has explicit EOF.
	if err := cmd.Start(); err != nil {
		t.Fatalf("branch shell failed to start: %v", err)
	}
	var orderingError error
	if control != nil {
		control.closeChildEnds()
		orderingError = control.run(item, func() error {
			if !deadline.Stop() {
				return fmt.Errorf("classifier startup watchdog elapsed")
			}
			cancel()
			return nil
		})
		if orderingError != nil && !control.finished {
			cancel()
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	err = cmd.Wait()
	if cmd.ProcessState == nil {
		t.Fatal("branch shell did not start and finish")
	}
	limit := ""
	if ctx.Err() != nil {
		limit = "context"
	} else if stdout.overflow || stderr.overflow {
		limit = "stdio"
	} else if errors.Is(err, exec.ErrWaitDelay) {
		limit = "wait"
	}
	if limit != item.wantLimit {
		t.Fatalf("branch carrier limit=%q, want %q", limit, item.wantLimit)
	}
	if limit == "stdio" {
		return npmBranchResult{}
	}
	var exitError *exec.ExitError
	if err != nil && !errors.As(err, &exitError) && limit != "context" {
		t.Fatal("branch shell carrier failed")
	}
	trace, err := os.Open(filepath.Join(dir, "trace"))
	if err != nil {
		t.Fatal("branch trace missing")
	}
	defer trace.Close()
	content, err := io.ReadAll(io.LimitReader(trace, 4097))
	if err != nil || len(content) > 4096 {
		t.Fatal("branch trace exceeds its bound")
	}
	return npmBranchResult{trace: string(content), stdout: stdout.String(), stderr: stderr.String(), exitCode: cmd.ProcessState.ExitCode(), orderingError: orderingError}
}

type npmBranchOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (output *npmBranchOutput) String() string { return output.buffer.String() }

func (output *npmBranchOutput) Write(content []byte) (int, error) {
	if output.buffer.Len()+len(content) > 16<<10 {
		output.overflow = true
		return 0, fmt.Errorf("branch stdio exceeds its bound")
	}
	return output.buffer.Write(content)
}
