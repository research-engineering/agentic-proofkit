package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
