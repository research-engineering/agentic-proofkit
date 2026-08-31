package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestSourceHygieneReadsStagedBlob(t *testing.T) {
	t.Parallel()

	for _, file := range sourceHygieneFixtureFiles(t) {
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

	for _, file := range sourceHygieneFixtureFiles(t) {
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

func TestSourceHygieneIgnoresTokenSubstringsInsideContentDigests(t *testing.T) {
	t.Parallel()

	scriptPath := sourceHygieneScriptPath(t)
	tempDir := t.TempDir()
	runCommand(t, tempDir, "git", "init")

	path := filepath.Join(tempDir, "contract.json")
	content := `{"canonicalDigest":"sha256:0123456789abcdef0123456789abcdef0123456789afcdef0123456789abcdef"}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write digest fixture: %v", err)
	}
	runCommand(t, tempDir, "git", "add", "contract.json")

	command := exec.Command("node", scriptPath)
	command.Dir = tempDir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("source hygiene rejected an identifier substring inside a digest: %v\n%s", err, output)
	}
}

func TestSourceHygieneRejectsMalformedUTF8(t *testing.T) {
	for _, test := range []struct {
		name      string
		stageBad  bool
		wantLabel string
	}{
		{name: "staged blob", stageBad: true, wantLabel: "tracked text object is not valid UTF-8"},
		{name: "worktree file", wantLabel: "worktree text file is not valid UTF-8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scriptPath := sourceHygieneScriptPath(t)
			tempDir := t.TempDir()
			runCommand(t, tempDir, "git", "init")
			path := filepath.Join(tempDir, "fixture.md")
			if err := os.WriteFile(path, []byte("clean\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			runCommand(t, tempDir, "git", "add", "fixture.md")
			malformed := []byte{'g', 'h', 'p', '_', 0xff}
			if test.stageBad {
				if err := os.WriteFile(path, malformed, 0o644); err != nil {
					t.Fatal(err)
				}
				runCommand(t, tempDir, "git", "add", "fixture.md")
			} else if err := os.WriteFile(path, malformed, 0o644); err != nil {
				t.Fatal(err)
			}

			command := exec.Command("node", scriptPath)
			command.Dir = tempDir
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("source hygiene accepted malformed UTF-8: %s", output)
			}
			if !strings.Contains(string(output), test.wantLabel) || strings.Contains(string(output), "ghp_") {
				t.Fatalf("source hygiene diagnostic = %q, want fixed label without input bytes", output)
			}
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

	return filepath.Join(sourceHygieneRepoRoot(t), "scripts", "source-hygiene.mjs")
}

func sourceHygieneFixtureFiles(t *testing.T) []string {
	t.Helper()

	repoRoot := sourceHygieneRepoRoot(t)
	command := exec.Command(
		"git",
		"ls-files",
		"-z",
		"--",
		"internal/command/requirementbrowser/assets",
	)
	command.Dir = repoRoot
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list tracked browser assets: %v", err)
	}

	extensions := make(map[string]struct{})
	for _, asset := range strings.Split(string(output), "\x00") {
		if asset == "" {
			continue
		}
		extension := filepath.Ext(asset)
		if extension == "" {
			t.Fatalf("tracked browser asset %q has no text extension", asset)
		}
		extensions[extension] = struct{}{}
	}
	if len(extensions) == 0 {
		t.Fatal("tracked browser asset inventory is empty")
	}

	files := []string{"README.md", "proof.py"}
	for extension := range extensions {
		files = append(files, "browser-asset"+extension)
	}
	sort.Strings(files)
	return files
}

func sourceHygieneRepoRoot(t *testing.T) string {
	t.Helper()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return repoRoot
}

func runCommand(t *testing.T, dir string, name string, args ...string) {
	t.Helper()

	command := exec.Command(name, args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, output)
	}
}
