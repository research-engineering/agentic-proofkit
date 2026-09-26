package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/textpolicy"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/processgroup"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/gitfixture"
)

func TestMain(m *testing.M) {
	if os.Args[len(os.Args)-1] == "text-policy-input-helper" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestNativeInventoryProjectsGitAndCurrentWorktree(t *testing.T) {
	root := inventoryRepository(t)
	initial := map[string]string{
		".gitignore":         "ignored/\n*.ignored\n",
		"clean.txt":          "clean\n",
		"deleted.txt":        "deleted\n",
		"modified.txt":       "committed\n",
		"recreated.txt":      "old\n",
		"recreated.ignored":  "old ignored\n",
		"staged-deleted.txt": "deleted from index\n",
		"staged.txt":         "committed staged file\n",
		"tracked.ignored":    "tracked despite ignore rule\n",
	}
	for path, content := range initial {
		inventoryWrite(t, root, path, []byte(content))
	}
	inventoryGit(t, root, "add", "-f", "--", ".")
	inventoryGit(t, root, "-c", "user.name=Inventory Fixture", "-c", "user.email=inventory@example.invalid", "commit", "-qm", "fixture")
	inventoryWrite(t, root, "modified.txt", []byte("worktree\x00\xff\r\n"))
	inventoryWrite(t, root, "staged.txt", []byte("index only\n"))
	inventoryWrite(t, root, "staged-add.txt", []byte("new index file\n"))
	inventoryGit(t, root, "add", "--", "staged.txt", "staged-add.txt")
	inventoryWrite(t, root, "staged.txt", []byte("current\tworktree\n"))
	inventoryWrite(t, root, "staged-add.txt", []byte("new current worktree\n"))
	inventoryRemove(t, root, "deleted.txt")
	inventoryGit(t, root, "rm", "--", "staged-deleted.txt", "recreated.txt", "recreated.ignored")
	inventoryWrite(t, root, "recreated.txt", []byte("recreated untracked\n"))
	inventoryWrite(t, root, "recreated.ignored", []byte("recreated now ignored\n"))
	inventoryWrite(t, root, "untracked.txt", []byte("untracked\n"))
	inventoryWrite(t, root, "ignored/hidden.txt", []byte("ignored\n"))

	// Check native Git operands independently, before observing the producer.
	assertGitPaths(t, root, []string{".gitignore", "clean.txt", "deleted.txt", "modified.txt", "staged-add.txt", "staged.txt", "tracked.ignored"}, "--cached")
	assertGitPaths(t, root, []string{"recreated.txt", "untracked.txt"}, "--others", "--exclude-standard")
	if got := string(inventoryGit(t, root, "show", ":staged.txt")); got != "index only\n" {
		t.Fatalf("staged operand = %q, want distinct index bytes", got)
	}
	want := []any{
		inventoryText(".gitignore", []byte(initial[".gitignore"])),
		inventoryText("clean.txt", []byte(initial["clean.txt"])),
		inventoryBare("deleted.txt", "missing"),
		inventoryText("modified.txt", []byte("worktree\x00\xff\r\n")),
		inventoryText("recreated.txt", []byte("recreated untracked\n")),
		inventoryText("staged-add.txt", []byte("new current worktree\n")),
		inventoryText("staged.txt", []byte("current\tworktree\n")),
		inventoryText("tracked.ignored", []byte(initial["tracked.ignored"])),
		inventoryText("untracked.txt", []byte("untracked\n")),
	}
	first, payload := inventoryPayload(t, root)
	assertInventoryPayload(t, payload, want)
	// A nested invocation must still read the repository-wide current worktree.
	second, nested := inventoryPayload(t, filepath.Join(root, "ignored"))
	assertInventoryPayload(t, nested, want)
	if !bytes.Equal(first, second) {
		t.Fatal("root and nested invocations did not produce byte-identical output")
	}
}

func TestNativeInventoryDeduplicatesUnmergedPaths(t *testing.T) {
	root := inventoryRepository(t)
	inventoryWrite(t, root, "conflict.txt", []byte("index blob\n"))
	oid := strings.TrimSpace(string(inventoryGit(t, root, "hash-object", "-w", "conflict.txt")))
	command := gitfixture.Command(root, "update-index", "--index-info")
	command.Stdin = strings.NewReader(fmt.Sprintf("100644 %s 1\tconflict.txt\n100644 %s 2\tconflict.txt\n100644 %s 3\tconflict.txt\n", oid, oid, oid))
	inventoryRequireSuccess(t, command)
	inventoryWrite(t, root, "conflict.txt", []byte("working conflict resolution\n"))
	inventoryWrite(t, root, "a.txt", []byte("first\n"))
	inventoryWrite(t, root, "z.txt", []byte("last\n"))
	assertGitPaths(t, root, []string{"conflict.txt", "conflict.txt", "conflict.txt"}, "--cached")
	_, payload := inventoryPayload(t, root)
	assertInventoryPayload(t, payload, []any{
		inventoryText("a.txt", []byte("first\n")),
		inventoryText("conflict.txt", []byte("working conflict resolution\n")),
		inventoryText("z.txt", []byte("last\n")),
	})
}

func TestNativeInventoryPreservesLiteralPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames cannot contain the literal tab/newline operands")
	}
	root := inventoryRepository(t)
	paths := []string{" leading and trailing .txt ", "names/line\nbreak.txt", "names/tab\tfile.txt"}
	want := []any{}
	for _, path := range paths {
		inventoryWrite(t, root, path, []byte("literal path\n"))
		want = append(want, inventoryText(path, []byte("literal path\n")))
	}
	inventoryGit(t, root, "add", "--", paths[0], paths[1])
	assertGitPaths(t, root, paths[:2], "--cached")
	assertGitPaths(t, root, paths[2:], "--others", "--exclude-standard")
	_, payload := inventoryPayload(t, filepath.Join(root, "names"))
	assertInventoryPayload(t, payload, want)
}

func TestNativeInventoryOmitsBinaryBytesByCaseFoldedSuffix(t *testing.T) {
	root := inventoryRepository(t)
	paths := []string{"alternate.pNg"}
	for _, suffix := range inventoryExpectedSuffixes() {
		paths = append(paths, "asset"+strings.ToUpper(suffix))
	}
	sort.Strings(paths)
	want := []any{}
	for _, path := range paths {
		inventoryWrite(t, root, path, []byte{0xff, 0xfe, 0, '\r'})
		want = append(want, inventoryBare(path, "present"))
	}
	for _, path := range []string{"not-binary.PNG.txt", "suffix.PNG/no-extension"} {
		data := []byte{0xff, 0, '\n'}
		inventoryWrite(t, root, path, data)
		want = append(want, inventoryText(path, data))
	}
	_, payload := inventoryPayload(t, root)
	assertInventoryPayload(t, payload, want)
}

func TestNativeInventoryEmptyRepository(t *testing.T) {
	root := inventoryRepository(t)
	assertGitPaths(t, root, []string{}, "--cached", "--others", "--exclude-standard")
	_, payload := inventoryPayload(t, root)
	assertInventoryPayload(t, payload, []any{})
}

func TestNativeInventoryGitFailuresHaveNoPartialStdout(t *testing.T) {
	t.Run("repository root", func(t *testing.T) {
		root := t.TempDir()
		command := inventoryCommand(t, root)
		command.Env = append(command.Env, "GIT_CEILING_DIRECTORIES="+filepath.Dir(root))
		assertInventoryFailure(t, command, "resolve git repository root:")
	})
	t.Run("file inventory", func(t *testing.T) {
		root := inventoryRepository(t)
		inventoryWrite(t, root, "visible.txt", []byte("must not leak partial inventory\n"))
		// Corrupt only this synthetic repository's index, without a PATH shim.
		inventoryWrite(t, root, ".git/index", []byte("invalid index\n"))
		inventoryGit(t, root, "rev-parse", "--show-toplevel")
		assertInventoryFailure(t, inventoryCommand(t, root), "list git files:")
	})
}

func TestNativeInventoryTextPolicyRoundtrip(t *testing.T) {
	root := inventoryRepository(t)
	inventoryWrite(t, root, "missing.txt", []byte("removed\n"))
	inventoryGit(t, root, "add", "--", "missing.txt")
	inventoryRemove(t, root, "missing.txt")
	inventoryWrite(t, root, "image.PNG", []byte{0xff, 0xfe})
	for _, item := range []struct {
		name     string
		content  string
		state    string
		exitCode int
		failures []string
	}{
		{"empty", "", "passed", 0, []string{}},
		{"pass", "good\ttext\n", "passed", 0, []string{}},
		{"fail", "bad \n", "failed", 1, []string{"text.txt:1: trailing whitespace"}},
	} {
		t.Run(item.name, func(t *testing.T) {
			inventoryWrite(t, root, "text.txt", []byte(item.content))
			_, payload := inventoryPayload(t, root)
			assertInventoryPayload(t, payload, []any{
				inventoryBare("image.PNG", "present"),
				inventoryBare("missing.txt", "missing"),
				inventoryText("text.txt", []byte(item.content)),
			})
			// Admit the real JSON output, not a reconstructed producer struct.
			result, err := textpolicy.Evaluate(payload)
			if err != nil {
				t.Fatalf("native output was not admitted: %v", err)
			}
			if result.ExitCode != item.exitCode || result.Report.State != item.state || !reflect.DeepEqual(result.Failures, item.failures) {
				t.Fatalf("text policy outcome = %#v", result)
			}
			if result.CheckedCount != 1 || result.BinarySkippedCount != 1 || result.MissingSkippedCount != 1 || result.Report.Summary["inputFileCount"] != 3 {
				t.Fatalf("text policy counts = %#v", result)
			}
			if result.Report.SchemaVersion != 1 || result.Report.ReportID != "proofkit.source.text-policy" || result.Report.ReportKind != "proofkit.text-policy" {
				t.Fatalf("text policy report identity = %#v", result.Report)
			}
		})
	}
}

func inventoryRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	inventoryGit(t, root, "init", "-q")
	return root
}

func inventoryWrite(t *testing.T, root, path string, content []byte) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func inventoryRemove(t *testing.T, root, path string) {
	t.Helper()
	if err := os.Remove(filepath.Join(root, path)); err != nil {
		t.Fatal(err)
	}
}

func inventoryGit(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	return inventoryRequireSuccess(t, gitfixture.Command(root, args...))
}

func inventoryRequireSuccess(t *testing.T, command *exec.Cmd) []byte {
	t.Helper()
	stdout, stderr, code := inventoryRun(t, command)
	if code != 0 {
		t.Fatalf("fixture command %q exited %d: %s", command.Args, code, stderr)
	}
	return stdout
}

func assertGitPaths(t *testing.T, root string, want []string, options ...string) {
	t.Helper()
	output := inventoryGit(t, root, append([]string{"ls-files", "-z"}, options...)...)
	got := []string{}
	if len(output) > 0 {
		if output[len(output)-1] != 0 {
			t.Fatalf("Git inventory lacks NUL delimiter: %q", output)
		}
		got = strings.Split(string(output[:len(output)-1]), "\x00")
	}
	t.Logf("native git ls-files %v: %q", options, got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Git fixture projection = %q, want %q", got, want)
	}
}

func inventoryCommand(t *testing.T, root string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^$", "--", "text-policy-input-helper")
	command.Dir = root
	command.Env = append(gitfixture.Command(root).Env,
		"GOCOVERDIR="+t.TempDir(),
	)
	return command
}

func inventoryRun(t *testing.T, template *exec.Cmd) ([]byte, []byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, template.Path, template.Args[1:]...)
	command.Dir, command.Env, command.Stdin = template.Dir, template.Env, template.Stdin
	command.WaitDelay = time.Second
	processgroup.Configure(command)
	// These cooperative fixtures start no background service; Run owns Wait.
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("process watchdog: %v", ctx.Err())
	}
	code := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() < 0 {
			t.Fatalf("unexpected process failure: %v; stderr=%q", err, stderr.Bytes())
		}
		code = exitError.ExitCode()
	}
	return stdout.Bytes(), stderr.Bytes(), code
}

func inventoryPayload(t *testing.T, root string) ([]byte, map[string]any) {
	t.Helper()
	stdout, stderr, code := inventoryRun(t, inventoryCommand(t, root))
	if code != 0 || len(stderr) != 0 {
		t.Fatalf("native scanner exit=%d stderr=%q stdout=%q", code, stderr, stdout)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		t.Fatalf("decode native output: %v; stdout=%q", err, stdout)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("native output contains trailing data: value=%#v error=%v", extra, err)
	}
	return stdout, payload
}

func assertInventoryFailure(t *testing.T, command *exec.Cmd, diagnostic string) {
	t.Helper()
	stdout, stderr, code := inventoryRun(t, command)
	if code != 1 || len(stdout) != 0 || !strings.HasPrefix(string(stderr), diagnostic) {
		t.Fatalf("native failure exit=%d stdout=%q stderr=%q, want exit 1, no stdout and %q", code, stdout, stderr, diagnostic)
	}
}

func inventoryText(path string, content []byte) map[string]any {
	return map[string]any{"path": path, "state": "present", "contentBase64": base64.StdEncoding.EncodeToString(content)}
}

func inventoryBare(path, state string) map[string]any {
	return map[string]any{"path": path, "state": state}
}

func inventoryExpectedSuffixes() []string {
	return []string{".avif", ".bin", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".pyc", ".svgz", ".tgz", ".webp", ".zip"}
}

func assertInventoryPayload(t *testing.T, got map[string]any, files []any) {
	t.Helper()
	suffixes := []any{}
	for _, suffix := range inventoryExpectedSuffixes() {
		suffixes = append(suffixes, suffix)
	}
	want := map[string]any{
		"schemaVersion": json.Number("1"),
		"reportId":      "proofkit.source.text-policy",
		"nonClaims":     []any{"Proofkit source text policy input does not claim consumer repository policy."},
		"policy": map[string]any{
			"allowTab": true, "asciiOnly": true, "binarySuffixes": suffixes,
			"rejectTrailingWhitespace": true, "requireFinalNewline": true,
		},
		"files": files,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native payload mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}
