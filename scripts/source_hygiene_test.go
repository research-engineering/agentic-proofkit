package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceHygieneReadsStagedBlob(t *testing.T) {
	t.Parallel()

	scriptPath := sourceHygieneScriptPath(t)
	tempDir := t.TempDir()
	runCommand(t, tempDir, "git", "init")

	bannedToken := strings.Join([]string{"a", "fc"}, "")
	readmePath := filepath.Join(tempDir, "README.md")
	if err := os.WriteFile(readmePath, []byte("leaked "+bannedToken+"\n"), 0o644); err != nil {
		t.Fatalf("write staged README: %v", err)
	}
	runCommand(t, tempDir, "git", "add", "README.md")
	if err := os.WriteFile(readmePath, []byte("clean\n"), 0o644); err != nil {
		t.Fatalf("clean worktree README: %v", err)
	}

	command := exec.Command("node", scriptPath)
	command.Dir = tempDir
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("source hygiene passed despite staged banned token:\n%s", output)
	}
	if !strings.Contains(string(output), "organization-specific text leaked into Proofkit: README.md") {
		t.Fatalf("source hygiene output=%s, want staged README failure", output)
	}
}

func TestSourceHygieneReadsTrackedWorktree(t *testing.T) {
	t.Parallel()

	scriptPath := sourceHygieneScriptPath(t)
	tempDir := t.TempDir()
	runCommand(t, tempDir, "git", "init")

	readmePath := filepath.Join(tempDir, "README.md")
	if err := os.WriteFile(readmePath, []byte("clean\n"), 0o644); err != nil {
		t.Fatalf("write clean README: %v", err)
	}
	runCommand(t, tempDir, "git", "add", "README.md")
	bannedToken := strings.Join([]string{"a", "fc"}, "")
	if err := os.WriteFile(readmePath, []byte("leaked "+bannedToken+"\n"), 0o644); err != nil {
		t.Fatalf("dirty worktree README: %v", err)
	}

	command := exec.Command("node", scriptPath)
	command.Dir = tempDir
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("source hygiene passed despite tracked worktree banned token:\n%s", output)
	}
	if !strings.Contains(string(output), "organization-specific text leaked into Proofkit: README.md") {
		t.Fatalf("source hygiene output=%s, want tracked worktree README failure", output)
	}
}

func sourceHygieneScriptPath(t *testing.T) string {
	t.Helper()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return filepath.Join(repoRoot, "scripts", "source-hygiene.mjs")
}

func runCommand(t *testing.T, dir string, name string, args ...string) {
	t.Helper()

	command := exec.Command(name, args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, output)
	}
}
