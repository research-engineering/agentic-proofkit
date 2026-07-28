package app

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func usage() string {
	return usageWithRenderer(cliexec.PathRenderer())
}

func usageWithRenderer(renderer cliexec.Renderer) string {
	lines := []string{"Usage:", "  agentic-proofkit [--json-layout pretty|compact] <command> [arguments]", "", "Commands:"}
	for _, descriptor := range commandDescriptors {
		lines = append(lines, "  "+commandUsageLine(descriptor))
	}
	lines = append(lines,
		"",
		"Discover command families:",
		"  "+renderer.DisplayCommand("help", "families"),
		"",
		"The Go runtime is the primary CLI implementation. CLI/JSON is the public cross-language contract.",
	)
	return strings.Join(lines, "\n") + "\n"
}
