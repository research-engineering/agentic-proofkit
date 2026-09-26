package main

import (
	"bytes"
	"context"
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
	os.Args = append([]string{"releasepreflight"}, os.Args[index+1:]...)
	main()
	os.Exit(0)
}

type npmBranchCase struct {
	name, payload, stderr  string
	viewExit, existingExit int
	publish, success       bool
	wantLimit              string
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
		header, body, err := npmAbsenceBranchFragment(raw, job)
		if err != nil {
			t.Fatal(err)
		}
		if job == "candidate" {
			t.Run("carrier/stdio bound", func(t *testing.T) {
				item := cases[0]
				item.wantLimit = "stdio"
				executeNPMAbsenceBranch(t, header+"printf '%17000s' x\n", body, item)
			})
			t.Run("carrier/blocked entrypoint timeout", func(t *testing.T) {
				item := cases[0]
				item.wantLimit = "context"
				result := executeNPMAbsenceBranch(t, header, body, item)
				if result.trace != "view\nabsent\nreaped\n" {
					t.Fatal("timeout must terminate and reap the blocked classifier before shell exit")
				}
			})
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
	timeout := 5 * time.Second
	if item.wantLimit == "context" {
		// Fault only the fixture input: main blocks opening this FIFO until
		// cancellation. The Bash parent must terminate and wait for that child.
		if err := syscall.Mkfifo(filepath.Join(dir, "blocked-report"), 0o600); err != nil {
			t.Fatal(err)
		}
		if strings.Count(body, "--error-file ./npm-view.json") != 1 {
			t.Fatal("blocked-input fault target drift")
		}
		body = strings.Replace(body, "--error-file ./npm-view.json", "--error-file ./blocked-report", 1)
		timeout = 2 * time.Second
	}
	script := `child=
cleanup() {
  if [[ -n "$child" ]]; then
    kill -TERM "$child" 2>/dev/null || :
    wait "$child" 2>/dev/null || :
    printf 'reaped\n' >> trace
    child=
  fi
}
trap cleanup EXIT
trap 'exit 124' TERM INT
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
      "$BRANCH_BINARY" -test.run='^TestNPMAbsenceBranchEntrypoint$' -test.timeout=3s -- "$@" </dev/null &
      child=$!
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + dir, "HOME=" + dir, "TMPDIR=" + dir, "PROOFKIT_BRANCH_ENTRYPOINT=1", "BRANCH_BINARY=" + binary, "BRANCH_PAYLOAD=" + item.payload, fmt.Sprintf("BRANCH_VIEW_EXIT=%d", item.viewExit), fmt.Sprintf("BRANCH_EXISTING_EXIT=%d", item.existingExit)}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = time.Second
	var stdout, stderr npmBranchOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Nil stdin is /dev/null; the sole spawned entrypoint also has explicit EOF.
	err = cmd.Run()
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
	return npmBranchResult{string(content), stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
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
