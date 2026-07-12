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

	for _, file := range []string{"README.md", "proof.py"} {
		file := file
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			scriptPath := sourceHygieneScriptPath(t)
			tempDir := t.TempDir()
			runCommand(t, tempDir, "git", "init")

			bannedToken := strings.Join([]string{"a", "fc"}, "")
			path := filepath.Join(tempDir, file)
			if err := os.WriteFile(path, []byte("leaked "+bannedToken+"\n"), 0o644); err != nil {
				t.Fatalf("write staged file: %v", err)
			}
			runCommand(t, tempDir, "git", "add", file)
			if err := os.WriteFile(path, []byte("clean\n"), 0o644); err != nil {
				t.Fatalf("clean worktree file: %v", err)
			}

			assertSourceHygieneRejects(t, scriptPath, tempDir, file, "staged")
		})
	}
}

func TestSourceHygieneReadsTrackedWorktree(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"README.md", "proof.py"} {
		file := file
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			scriptPath := sourceHygieneScriptPath(t)
			tempDir := t.TempDir()
			runCommand(t, tempDir, "git", "init")

			path := filepath.Join(tempDir, file)
			if err := os.WriteFile(path, []byte("clean\n"), 0o644); err != nil {
				t.Fatalf("write clean file: %v", err)
			}
			runCommand(t, tempDir, "git", "add", file)
			bannedToken := strings.Join([]string{"a", "fc"}, "")
			if err := os.WriteFile(path, []byte("leaked "+bannedToken+"\n"), 0o644); err != nil {
				t.Fatalf("dirty worktree file: %v", err)
			}

			assertSourceHygieneRejects(t, scriptPath, tempDir, file, "tracked worktree")
		})
	}
}

func assertSourceHygieneRejects(t *testing.T, scriptPath string, repoRoot string, file string, evidenceClass string) {
	t.Helper()
	command := exec.Command("node", scriptPath)
	command.Dir = repoRoot
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("source hygiene passed despite %s banned token:\n%s", evidenceClass, output)
	}
	want := "organization-specific text leaked into Proofkit: " + file
	if !strings.Contains(string(output), want) {
		t.Fatalf("source hygiene output=%s, want %s failure", output, file)
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
