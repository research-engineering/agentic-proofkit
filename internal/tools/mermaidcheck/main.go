package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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
		fmt.Fprintln(os.Stderr, err)
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
	cmd := exec.Command("git", "ls-files", "*.md")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list tracked Markdown files: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
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
