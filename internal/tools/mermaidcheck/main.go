package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

var (
	htmlTagPattern        = regexp.MustCompile(`(?i)<\s*/?\s*(a|b|br|code|div|em|i|p|span|strong|sub|sup|u)(\s[^>\n]*)?/?>`)
	arrowInLabelPattern   = regexp.MustCompile(`[\[\(][^\]\)\n]*-+>[^\]\)\n]*[\]\)]`)
	quotedDottedEdgeLabel = regexp.MustCompile(`-\.\s*"[^"\n]+"\s*\.->`)
)

type diagramBlock struct {
	path      string
	startLine int
	lines     []string
}

type checkError struct {
	path string
	line int
	msg  string
}

func (e checkError) Error() string {
	return fmt.Sprintf("%s:%d: %s", e.path, e.line, e.msg)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	files := args
	if len(files) == 0 {
		var err error
		files, err = markdownFilesFromGit()
		if err != nil {
			return err
		}
	}

	blockCount := 0
	for _, file := range files {
		blocks, err := extractMermaidBlocks(file)
		if err != nil {
			return err
		}
		for _, block := range blocks {
			blockCount++
			if err := validateBlock(block); err != nil {
				return err
			}
		}
	}

	fmt.Fprintf(stdout, "checked %d Mermaid diagram(s) in %d Markdown file(s)\n", blockCount, len(files))
	return nil
}

func markdownFilesFromGit() ([]string, error) {
	return markdownFilesFromGitAt(".")
}

func markdownFilesFromGitAt(dir string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.md")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list candidate Markdown files: %w", err)
	}
	decoded, err := unicodepolicy.DecodeUTF8(out)
	if err != nil {
		return nil, fmt.Errorf("candidate Markdown file inventory is not valid UTF-8")
	}

	var files []string
	seen := make(map[string]struct{})
	for _, path := range strings.Split(decoded, "\x00") {
		if path == "" {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect candidate Markdown file %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func extractMermaidBlocks(path string) ([]diagramBlock, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	var blocks []diagramBlock
	var current *diagramBlock
	lineNumber := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if current == nil {
			if isMermaidFenceOpen(trimmed) {
				current = &diagramBlock{path: path, startLine: lineNumber + 1}
			}
			continue
		}

		if isFenceClose(trimmed) {
			blocks = append(blocks, *current)
			current = nil
			continue
		}
		current.lines = append(current.lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if current != nil {
		return nil, checkError{path: path, line: current.startLine - 1, msg: "unterminated Mermaid fenced block"}
	}
	return blocks, nil
}

func isMermaidFenceOpen(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "```") {
		return false
	}
	info := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
	if info == "" {
		return false
	}
	fields := strings.Fields(info)
	return len(fields) > 0 && strings.EqualFold(fields[0], "mermaid")
}

func isFenceClose(trimmed string) bool {
	return strings.HasPrefix(trimmed, "```")
}

func validateBlock(block diagramBlock) error {
	if len(strings.TrimSpace(strings.Join(block.lines, "\n"))) == 0 {
		return checkError{path: block.path, line: block.startLine, msg: "empty Mermaid diagram"}
	}

	for i, line := range block.lines {
		lineNumber := block.startLine + i
		if htmlTagPattern.MatchString(line) {
			return checkError{path: block.path, line: lineNumber, msg: "HTML tags are not allowed in Mermaid diagrams; use plain labels for GitHub rendering stability"}
		}
		if arrowInLabelPattern.MatchString(line) {
			return checkError{path: block.path, line: lineNumber, msg: "node labels must not contain arrow tokens; model relationships as edges"}
		}
		if quotedDottedEdgeLabel.MatchString(line) {
			return checkError{path: block.path, line: lineNumber, msg: "quoted dotted-edge labels are not GitHub-stable; use pipe labels such as A -.->|label| B"}
		}
	}
	return nil
}
