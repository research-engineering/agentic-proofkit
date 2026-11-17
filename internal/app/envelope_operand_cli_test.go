package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestRouteEnvelopeWireArgvOpensOriginalPreparedFile(t *testing.T) {
	t.Chdir(t.TempDir())
	writeSource := func(path, id string) {
		t.Helper()
		source := cliRequirementSource("The consumer preserves the admitted behavior.")
		source["sourceId"] = id
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(cliJSON(source)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A silently substituted display marker would still be a readable valid file.
	writeSource(admit.DiagnosticRedactionMarker, "consumer.decoy")
	for _, path := range []string{"inputs/task-validation.json", strings.Repeat("segment/", 80) + "requirements.json"} {
		writeSource(path, "consumer.original")
		packet := runCLIForJSON(t, []string{"agent-route", "--input", "-", "--agent-envelope", "--agent-envelope-mode", "full"}, cliJSON(map[string]any{
			"schemaVersion": json.Number("1"), "routeId": "consumer.route.prepared-input",
			"goal": "validate_requirement_source", "mode": "observe",
			"availableInputs": []any{map[string]any{"kind": "requirement_source", "ref": path}},
		}))
		commands := packet["commands"].([]any)
		if len(commands) != 1 {
			t.Fatalf("path %q: commands=%v, want one executable route", path, commands)
		}
		wireArgv := commands[0].(map[string]any)["argv"].([]any)
		argv := make([]string, len(wireArgv))
		for index, value := range wireArgv {
			argv[index] = value.(string)
		}
		if len(argv) != 4 || argv[0] != "agentic-proofkit" || argv[1] != "requirement-source-admission" || argv[2] != "--input" || argv[3] != path {
			t.Fatalf("wire argv changed the intended invocation: %v", argv)
		}
		// Run the decoded command, rather than reusing its producer's input map.
		report := runCLIForJSON(t, argv[1:], "")
		if report["reportId"] != "consumer.original" || report["state"] != "passed" {
			t.Fatalf("wire command did not admit the original file: %v", report)
		}
	}
}
