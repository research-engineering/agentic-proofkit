package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestREADMEWorkflowRoutes(t *testing.T) {
	t.Parallel()
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(content)
	args, err := installedREADMEWorkflowRoutes(readme)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args, []string{"adopt", "plan", "--repo-root", ".", "--mode", "audit-from-code", "--format", "text"}) {
		t.Fatal("README first action changed its read-only root and trust mode")
	}
	for _, pair := range [][2]string{
		{"adopt plan --repo-root .", "adopt materialize apply --repo-root ."},
		{"--mode audit-from-code", "--mode code-baseline"},
		{"status --repo-root . --format text", "status --repo-root ."},
		{"next --repo-root . --format text", "status --repo-root . --format text"},
		{"view --repo-root . --serve", "view --repo-root ."},
		{"view --repo-root . --serve", "view --repo-root . --serve --open"},
		{"For an already materialized, current project:", ""},
		{"For an already materialized, current project:", "Immediately after the read-only plan, run:"},
		{"<!-- proofkit:first-action:start -->", ""},
		{"<!-- proofkit:first-action:end -->", "<!-- proofkit:first-action:start -->"},
		{"<!-- proofkit:daily-workflow:end -->", "<!-- proofkit:daily-workflow:end -->\n<!-- proofkit:daily-workflow:end -->"},
		{"npm exec --offline -- agentic-proofkit adopt", "npx agentic-proofkit adopt"},
	} {
		if !strings.Contains(readme, pair[0]) {
			t.Fatal("README route mutation missed its subject")
		}
		if _, err := installedREADMEWorkflowRoutes(strings.ReplaceAll(readme, pair[0], pair[1])); err == nil {
			t.Fatal("mutated README workflow admitted")
		}
	}
}
