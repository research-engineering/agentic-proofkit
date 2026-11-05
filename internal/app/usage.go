package app

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func usage() string {
	return usageWithRenderer(cliexec.PathRenderer())
}

func usageWithRenderer(renderer cliexec.Renderer) string {
	integration, _ := commandDescriptorFor("integration-source")
	lines := []string{
		"Usage:",
		"  agentic-proofkit [--json-layout pretty|compact] <command> [arguments]",
		"  " + renderer.DisplayCommand("--version"),
		"",
		"Start here: the agent bootstrap, then the project's next action:",
		"  " + renderer.DisplayCommand("integration", "source") + " --tool <" + strings.Join(integration.flagValueChoices["--tool"], "|") + "> --format text",
		"  " + renderer.DisplayCommand("next") + " --repo-root <path>",
		"",
		"Discover command families:",
		"  " + renderer.DisplayCommand("help", "families"),
		"",
		"Commands:",
	}
	for _, descriptor := range commandDescriptors {
		lines = append(lines, "  "+commandUsageLine(descriptor))
	}
	lines = append(lines,
		"",
		"The Go runtime is the primary CLI implementation. CLI/JSON is the public cross-language contract.",
	)
	return strings.Join(lines, "\n") + "\n"
}
