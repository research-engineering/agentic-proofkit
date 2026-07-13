package app

import "strings"

func usage() string {
	lines := []string{"Usage:", "  agentic-proofkit [--json-layout pretty|compact] <command> [arguments]", "", "Commands:"}
	for _, descriptor := range commandDescriptors {
		lines = append(lines, "  "+commandUsageLine(descriptor))
	}
	lines = append(lines,
		"",
		"The Go runtime is the primary CLI implementation. CLI/JSON is the public cross-language contract.",
	)
	return strings.Join(lines, "\n") + "\n"
}
