package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Executes the actual tag-verification step with host effects replaced by
// shell functions: the GitHub token must authenticate both API reads through
// stdin and never appear in any command's arguments.
func TestReleaseTagVerificationKeepsTokenOutOfArgv(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	job, ok := workflow.Jobs["publish-readiness"]
	if !ok {
		t.Fatal("release workflow has no publish-readiness job")
	}
	index, err := uniqueStepIndex(job.Steps, "Verify tag source and channel readiness")
	if err != nil || index < 0 {
		t.Fatalf("tag verification step index=%d err=%v", index, err)
	}
	step := job.Steps[index]
	if normalizedExpression(withString(step.Env, "GITHUB_TOKEN")) != "github.token" {
		t.Fatalf("tag verification step no longer receives the job token: %#v", step.Env)
	}
	const token = "ghs_syntheticTokenForArgvOracle0123456789"
	for _, control := range []struct {
		name   string
		setup  string
		failed bool
	}{
		{name: "verified tag reads"},
		{name: "api failure", setup: "curl_status=22", failed: true},
	} {
		t.Run(control.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, path := range []string{"artifacts/publish/npm-publish-dry-run.json", "artifacts/pypi/python-packages.json", "artifacts/pypi/agentic_proofkit-1.2.3-py3-none-any.whl"} {
				if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(path)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, path), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			argvLog, stdinLog := filepath.Join(dir, "argv.log"), filepath.Join(dir, "stdin.log")
			harness := `record() { printf '%s\n' "$*" >> "$ARGV_LOG"; }
curl_status=0
python3() {
  record python3 "$@"
  case "$*" in
    *package.json*) echo 1.2.3 ;;
    *'["sha"]'*) echo 0123abcd ;;
    *'["type"]'*) echo tag ;;
    *) return 2 ;;
  esac
}
git() {
  record git "$@"
  case "$1" in rev-list) echo 89abcdef ;; merge-base) return 0 ;; *) return 2 ;; esac
}
go() { record go "$@"; }
curl() {
  record curl "$@"
  [[ " $* " == *" @- "* ]] && cat >> "$STDIN_LOG"
  [[ "$curl_status" == 0 ]] || return "$curl_status"
  printf '{"object":{"sha":"0123abcd","type":"tag"}}'
}
` + control.setup + "\n" + strings.ReplaceAll(step.Run, "/tmp/proofkit-", dir+"/proofkit-")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", harness)
			command.Dir = dir
			command.Env = append(os.Environ(),
				"ARGV_LOG="+argvLog, "STDIN_LOG="+stdinLog, "EXPECTED_VERSION=", "GITHUB_TOKEN="+token,
				"REQUIRE_VERIFIED_TAG=true", "GITHUB_REF_TYPE=tag", "GITHUB_REF_NAME=v1.2.3", "GITHUB_REF_PROTECTED=true",
				"GITHUB_REPOSITORY=example/repository", "GITHUB_API_URL=https://api.example.invalid",
			)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil || (err != nil) != control.failed {
				t.Fatalf("step failure=%v timeout=%v, want failure=%v; output=%s", err, ctx.Err(), control.failed, output)
			}
			argv, err := os.ReadFile(argvLog)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(argv), token) {
				t.Fatalf("GitHub token reached command arguments:\n%s", argv)
			}
			calls := strings.Count(string(argv), "curl ")
			stdin, _ := os.ReadFile(stdinLog)
			if strings.Count(string(stdin), "Authorization: Bearer "+token+"\n") != calls || calls == 0 {
				t.Fatalf("curl calls=%d did not each authenticate through stdin: %q", calls, stdin)
			}
			if !control.failed && calls != 2 {
				t.Fatalf("verified tag path made %d API reads, want 2:\n%s", calls, argv)
			}
		})
	}
}
