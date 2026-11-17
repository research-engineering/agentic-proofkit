package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestAgentRouteRefusesEmbeddedProjectSignatureInEveryCarrier(t *testing.T) {
	key := ""
	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		if fixture.Name == "openai_key" {
			key = fixture.Input
		}
	}
	if key == "" {
		t.Fatal("missing protected project-key fixture")
	}
	for _, extra := range [][]string{nil, {"--agent-envelope"}, {"--agent-envelope", "--agent-envelope-mode", "full"}} {
		for _, path := range []string{"inputs/prefix" + key + "suffix.json", "inputs/task-validation.json"} {
			input := map[string]any{
				"schemaVersion": json.Number("1"), "routeId": "consumer.route.path-privacy",
				"goal": "validate_requirement_source", "mode": "observe",
				"availableInputs": []any{map[string]any{"kind": "requirement_source", "ref": path}},
			}
			argv := append([]string{"agent-route", "--input", "-"}, extra...)
			var stdout, stderr bytes.Buffer
			code := Run(t.Context(), argv, strings.NewReader(cliJSON(input)), &stdout, &stderr)
			secret := strings.Contains(path, key)
			if (code != 0) != secret {
				t.Fatalf("carrier %v: exit=%d, want refusal=%t", extra, code, secret)
			}
			if strings.Contains(stdout.String(), key) || strings.Contains(stderr.String(), key) {
				t.Fatal("protected project signature reached a report sink")
			}
			if !secret && !strings.Contains(stdout.String(), path) {
				t.Fatal("ordinary task path was lost from successful guidance")
			}
		}
	}
}
