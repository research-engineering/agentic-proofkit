package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMermaidCheckAcceptsGitHubSafeFlowchart(t *testing.T) {
	const doc = "# Example\n\n```mermaid\nflowchart LR\n    A[Repository state] --> B[Adoption mode]\n    B --> C[Repo-owned inputs]\n    C --> D[Proofkit admission]\n```\n"
	var out bytes.Buffer
	if err := runForTest(map[string]string{"README.md": doc}, &out); err != nil {
		t.Fatalf("expected diagram to pass: %v", err)
	}
	if !strings.Contains(out.String(), "checked 1 Mermaid diagram") {
		t.Fatalf("expected checked count, got %q", out.String())
	}
}

func TestMermaidCheckRejectsHTMLTags(t *testing.T) {
	const doc = "```mermaid\nflowchart LR\n    A[Line<br/>break] --> B[Next]\n```\n"
	err := checkFileContent("README.md", doc)
	if err == nil {
		t.Fatal("expected HTML tag rejection")
	}
	if got := errorText(err); !strings.Contains(got, "HTML tags") {
		t.Fatalf("expected HTML tag message, got %q", got)
	}
}

func TestMermaidCheckRejectsArrowInsideNodeLabel(t *testing.T) {
	const doc = "```mermaid\nflowchart LR\n    A[requirements -> scenarios] --> B[Proof]\n```\n"
	err := checkFileContent("README.md", doc)
	if err == nil {
		t.Fatal("expected arrow-in-label rejection")
	}
	if got := errorText(err); !strings.Contains(got, "node labels") {
		t.Fatalf("expected label message, got %q", got)
	}
}

func TestMermaidCheckRejectsQuotedDottedEdgeLabel(t *testing.T) {
	const doc = "```mermaid\nflowchart LR\n    A -. \"optional\" .-> B\n```\n"
	err := checkFileContent("README.md", doc)
	if err == nil {
		t.Fatal("expected dotted-edge label rejection")
	}
	if got := errorText(err); !strings.Contains(got, "quoted dotted-edge labels") {
		t.Fatalf("expected dotted-edge message, got %q", got)
	}
}

func TestMarkdownFilesFromGitUsesCandidateWorktree(t *testing.T) {
	dir := t.TempDir()
	runGitForTest(t, dir, "init", "--quiet")

	writeTestFile(t, dir, ".gitignore", "ignored.md\n")
	writeTestFile(t, dir, "deleted.md", "# Deleted\n")
	writeTestFile(t, dir, "kept.md", "# Kept\n")
	runGitForTest(t, dir, "add", ".gitignore", "deleted.md", "kept.md")

	if err := os.Remove(filepath.Join(dir, "deleted.md")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "new.md", "# New\n")
	writeTestFile(t, dir, "ignored.md", "# Ignored\n")

	got, err := markdownFilesFromGitAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kept.md", "new.md"}
	if !slices.Equal(got, want) {
		t.Fatalf("candidate Markdown files = %v, want %v", got, want)
	}
}

func checkFileContent(path, content string) error {
	tmp, err := os.CreateTemp("", "proofkit-mermaid-*.md")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	blocks, err := extractMermaidBlocks(tmp.Name())
	if err != nil {
		return err
	}
	for _, block := range blocks {
		block.path = path
		if err := validateBlock(block); err != nil {
			return err
		}
	}
	return nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	var checkErr checkError
	if errors.As(err, &checkErr) {
		return checkErr.msg
	}
	return err.Error()
}

func runForTest(files map[string]string, stdout *bytes.Buffer) error {
	var names []string
	dir, err := os.MkdirTemp("", "proofkit-mermaid-run-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
		names = append(names, path)
	}
	if stdout == nil {
		stdout = &bytes.Buffer{}
	}
	return run(names, stdout)
}

func runGitForTest(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeTestFile(t *testing.T, dir, path, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
