package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func installedREADMEWorkflowRoutes(content string) ([]string, error) {
	blocks := []struct {
		name     string
		premise  string
		commands []string
	}{
		{"first-action", "", []string{"adopt plan --repo-root . --mode audit-from-code --format text"}},
		{"daily-workflow", "For an already materialized, current project:", []string{
			"status --repo-root . --format text",
			"next --repo-root . --format text",
			"view --repo-root . --serve",
		}},
	}
	for _, block := range blocks {
		startMarker := "<!-- proofkit:" + block.name + ":start -->"
		endMarker := "<!-- proofkit:" + block.name + ":end -->"
		if strings.Count(content, startMarker) != 1 || strings.Count(content, endMarker) != 1 {
			return nil, fmt.Errorf("installed README workflow markers must occur exactly once")
		}
		start := strings.Index(content, startMarker) + len(startMarker)
		end := strings.Index(content, endMarker)
		if end <= start {
			return nil, fmt.Errorf("installed README workflow marker order is invalid")
		}
		lines := []string{"```bash"}
		if block.premise != "" {
			lines = append([]string{block.premise, ""}, lines...)
		}
		for _, command := range block.commands {
			lines = append(lines, installedNPMExecCommandPrefix+command)
		}
		lines = append(lines, "```")
		if strings.TrimSpace(content[start:end]) != strings.Join(lines, "\n") {
			return nil, fmt.Errorf("installed README workflow must preserve its prerequisite and exact commands")
		}
	}
	return strings.Fields(blocks[0].commands[0]), nil
}

func verifyInstalledREADMEWorkflow(consumer string) (returnErr error) {
	readme, err := os.ReadFile(filepath.Join(consumer, filepath.FromSlash(installedNPMPackageRelativeRoot), installedNPMReadmeRelativePath))
	if err != nil {
		return fmt.Errorf("read installed README workflow: %w", err)
	}
	args, err := installedREADMEWorkflowRoutes(string(readme))
	if err != nil {
		return err
	}
	// The empty child still resolves the installed npm dependency from its parent.
	root, err := os.MkdirTemp(consumer, "readme-first-action-")
	if err != nil {
		return fmt.Errorf("create README first-action repository: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(root)) }()
	result, err := runInstalledWithInput(root, nil, args...)
	if err != nil {
		return fmt.Errorf("execute installed README first action: %w", err)
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 || bytes.Contains(result.Stdout, []byte("\x1b")) || len(result.Stdout) > 32<<10 {
		return fmt.Errorf("installed README first action must produce bounded successful uncolored text")
	}
	for _, line := range []string{
		"Adoption plan", "Mode: audit-from-code", "State: authoring_required",
		"Inventory: 0 recognized, 0 omitted, 0 opaque", "Authority: candidate-only; consuming repository owner",
		"Evidence template: native-evidence-guidance",
	} {
		if !strings.Contains("\n"+string(result.Stdout), "\n"+line+"\n") {
			return fmt.Errorf("installed README first action lost its candidate-only empty-repository outcome")
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("inspect README first-action repository: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("installed README first action must not materialize repository files")
	}
	return nil
}
