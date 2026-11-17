package gradualadoption

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestGuidanceSharedDisplayRetainsIndependentCallerOrigin(t *testing.T) {
	path := "inputs/" + strings.Repeat("a", 550) + ".json"
	display := cliexec.DisplayArgv([]string{"agentic-proofkit", "witness-plan", "--input", path})
	for _, caller := range []bool{false, true} {
		for _, bounded := range []bool{false, true} {
			t.Run(fmt.Sprintf("caller=%t/bounded=%t", caller, bounded), func(t *testing.T) {
				input := validGuidanceInput()
				agent := input["agentGuidance"].(map[string]any)
				agent["proofkitCommands"] = map[string]any{"witness-plan": path}
				agent["commands"] = []any{}
				if caller {
					agent["commands"] = []any{display}
				}
				if bounded {
					modernization := guidanceInputWithCandidateBoundary("observe")["modernization"].(map[string]any)
					template := modernization["candidateBoundaries"].([]any)[0]
					candidates := []any{}
					for index := 0; index < agentenvelope.MaxContextRefs+4; index++ {
						candidate := invocationJSON(t, template).(map[string]any)
						candidate["boundaryId"] = fmt.Sprintf("candidate.boundary.%03d", index)
						candidates = append(candidates, candidate)
					}
					modernization["candidateBoundaries"] = candidates
					input["modernization"] = modernization
				}
				envelope, exit, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
				if err != nil || exit != 0 {
					t.Fatalf("guidance failed: exit=%d err=%v", exit, err)
				}
				commands := envelope["commands"].([]any)
				if bounded && !caller {
					if len(commands) != 0 {
						t.Fatal("generated-only command survived loss of its typed context")
					}
					return
				}
				if len(commands) != 1 {
					t.Fatal("merged command lost its unique admitted origin")
				}
				command := commands[0].(map[string]any)
				if command["commandId"] != "proofkit.agent.command.001" {
					t.Fatal("caller fallback changed command identity")
				}
				if bounded {
					if command["argv"] != nil || command["command"] != admit.RedactDiagnosticValue(display) || command["command"] == display {
						t.Fatal("caller fallback is not the original scalar projection without argv")
					}
				} else if command["argv"] == nil || command["command"] != display {
					t.Fatal("retained typed form was lost or scalar-truncated")
				}
				found := false
				for _, raw := range envelope["actionPlan"].([]any) {
					for _, id := range raw.(map[string]any)["commandIds"].([]any) {
						found = found || id == command["commandId"]
					}
				}
				if !found {
					t.Fatal("retained caller command lost its action reference")
				}
			})
		}
	}
}
