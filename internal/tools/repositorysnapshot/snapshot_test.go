package repositorysnapshot

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaterializeBindsCopiedBytesAndRejectsLiveMutation(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "a.txt"), "alpha")
	if err := os.Chmod(filepath.Join(root, "a.txt"), 0o760); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "a.txt")
	runGit(t, root, "commit", "-m", "initial")
	destination := t.TempDir()

	snapshot, err := Materialize(root, destination)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	if err := ValidateMaterialized(destination, snapshot); err != nil {
		t.Fatalf("ValidateMaterialized() error = %v", err)
	}
	writeFile(t, filepath.Join(root, "a.txt"), "mutated")
	current, err := Capture(root)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if EqualIdentity(snapshot, current) {
		t.Fatal("live mutation preserved snapshot identity")
	}
	content, err := os.ReadFile(filepath.Join(destination, "a.txt"))
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	if string(content) != "alpha" {
		t.Fatalf("materialized content = %q, want alpha", content)
	}
	info, err := os.Stat(filepath.Join(destination, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o760 {
		t.Fatalf("materialized mode = %04o, want 0760", got)
	}
}

func TestMaterializeRejectsSymlinkAndNonEmptyDestination(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "target.txt"), "target")
	const callerPath = "caller-path-sentinel"
	if err := os.Symlink("target.txt", filepath.Join(root, callerPath)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	runGit(t, root, "add", "target.txt", callerPath)
	runGit(t, root, "commit", "-m", "initial")
	if _, err := Materialize(root, t.TempDir()); err == nil || !strings.Contains(err.Error(), "symlinks are not admitted") {
		t.Fatalf("Materialize() symlink error = %v", err)
	} else if strings.Contains(err.Error(), callerPath) {
		t.Fatalf("Materialize() leaked caller-owned path: %v", err)
	}

	plainRoot := initializeRepository(t)
	writeFile(t, filepath.Join(plainRoot, "a.txt"), "alpha")
	runGit(t, plainRoot, "add", "a.txt")
	runGit(t, plainRoot, "commit", "-m", "initial")
	destination := t.TempDir()
	writeFile(t, filepath.Join(destination, "occupied"), "x")
	if _, err := Materialize(plainRoot, destination); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("Materialize() non-empty destination error = %v", err)
	}
}

func TestMaterializeRejectsSymlinkedDestinationInsideSource(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "tracked.txt"), "tracked")
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "initial")
	insideSource := filepath.Join(root, "snapshot-output")
	if err := os.Mkdir(insideSource, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.Symlink(insideSource, destination); err != nil {
		t.Fatal(err)
	}

	if _, err := Materialize(root, destination); err == nil || !strings.Contains(err.Error(), "must be outside the source root") {
		t.Fatalf("Materialize() error = %v, want physical source-containment rejection", err)
	}
	entries, err := os.ReadDir(insideSource)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("source-contained destination was mutated: %v", entries)
	}
}

func TestCaptureIncludesUntrackedAndIgnoresIgnoredFiles(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
	writeFile(t, filepath.Join(root, "tracked.txt"), "tracked")
	runGit(t, root, "add", ".gitignore", "tracked.txt")
	runGit(t, root, "commit", "-m", "initial")
	writeFile(t, filepath.Join(root, "untracked.txt"), "untracked")
	writeFile(t, filepath.Join(root, "ignored.txt"), "ignored")

	snapshot, err := Capture(root)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	joined := strings.Join(snapshot.Paths, ",")
	if !strings.Contains(joined, "untracked.txt") || strings.Contains(joined, "ignored.txt") {
		t.Fatalf("snapshot paths = %v", snapshot.Paths)
	}
}

func TestValidRevisionAdmitsOnlyGitObjectIdentityAndOptionalSnapshotDigest(t *testing.T) {
	valid := []string{
		strings.Repeat("a", 40),
		strings.Repeat("b", 64),
		strings.Repeat("c", 40) + "+worktree.sha256:" + strings.Repeat("d", 64),
	}
	for _, value := range valid {
		if !ValidRevision(value) {
			t.Fatalf("ValidRevision(%q) = false", value)
		}
	}
	invalid := []string{
		"",
		"caller-secret-sentinel",
		strings.Repeat("A", 40),
		strings.Repeat("a", 39),
		strings.Repeat("a", 40) + "+worktree.sha256:invalid",
		strings.Repeat("a", 40) + "+worktree.sha256:" + strings.Repeat("b", 64) + "+worktree.sha256:" + strings.Repeat("c", 64),
	}
	for _, value := range invalid {
		if ValidRevision(value) {
			t.Fatalf("ValidRevision(%q) = true", value)
		}
	}
}

func TestValidateMaterializedRejectsSurplusFile(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "tracked.txt"), "tracked")
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "initial")
	destination := t.TempDir()
	snapshot, err := Materialize(root, destination)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(destination, "surplus.txt"), "surplus")
	if err := ValidateMaterialized(destination, snapshot); err == nil || !strings.Contains(err.Error(), "inventory is stale") {
		t.Fatalf("ValidateMaterialized() error = %v, want surplus-file rejection", err)
	}
}

func TestCaptureContextTerminatesCanceledGitProcessGroup(t *testing.T) {
	bin := t.TempDir()
	gitPath := filepath.Join(bin, "git")
	if err := os.WriteFile(gitPath, []byte("#!/bin/sh\n/bin/sleep 10\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := CaptureContext(ctx, t.TempDir()); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("CaptureContext() error = %v, want cancellation", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("CaptureContext() cancellation took %s", elapsed)
	}
}

func TestCaptureContextTerminatesGitProcessGroupOnOutputOverflow(t *testing.T) {
	bin := t.TempDir()
	gitPath := filepath.Join(bin, "git")
	script := "#!/bin/sh\n/bin/dd if=/dev/zero bs=17825792 count=1 1>&2\n/bin/sleep 10\n"
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	started := time.Now()
	if _, err := CaptureContext(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "output exceeds resource limit") {
		t.Fatalf("CaptureContext() error = %v, want output-limit rejection", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("CaptureContext() output-limit termination took %s", elapsed)
	}
}

func TestCaptureRejectsSuccessfulGitDiagnosticsWithoutEcho(t *testing.T) {
	bin := t.TempDir()
	gitPath := filepath.Join(bin, "git")
	const diagnostic = "sensitive diagnostic sentinel"
	script := "#!/bin/sh\nprintf 'tracked.txt\\0'\nprintf '" + diagnostic + "' 1>&2\n"
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	_, err := Capture(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "emitted diagnostics") {
		t.Fatalf("Capture() error = %v, want diagnostics rejection", err)
	}
	if strings.Contains(err.Error(), diagnostic) {
		t.Fatalf("Capture() leaked git diagnostics: %v", err)
	}
}

func initializeRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.invalid")
	runGit(t, root, "config", "user.name", "Test")
	return root
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
