package adoptioncontract

import (
	"strings"
	"testing"
)

func TestAggregateBootstrapRefusesUnsafePayloadInEveryOutputMode(t *testing.T) {
	marker := "api_" + "key=synthetic-aggregate-fixture"
	for _, options := range []Options{{Mode: "bootstrap"}, {Mode: "bootstrap", AgentEnvelope: true}, {Mode: "bootstrap", MaterializationManifest: true}} {
		input := validAggregateEnvelope()
		gradual := input["gradual"].(map[string]any)
		gradual["input"].(map[string]any)["budget"].(map[string]any)["unadmittedExtra"] = marker
		output, exit, err := Build(input, options)
		if exit != 1 {
			t.Fatal("aggregate bypassed bootstrap refusal")
		}
		if options.AgentEnvelope {
			packet, ok := output.(map[string]any)
			if !ok {
				t.Fatal("repair envelope must be an object")
			}
			source, ok := packet["sourceReport"].(map[string]any)
			if err != nil || !ok || source["reportId"] != "proofkit.agent-envelope.invalid-input" || source["state"] != "failed" {
				t.Fatal("aggregate lost the invalid-input repair envelope")
			}
		} else if err == nil || stableJSON(t, output) != "null" {
			t.Fatal("aggregate returned unsafe ordinary output")
		}
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Fatal("error disclosed caller text")
		}
		if strings.Contains(stableJSON(t, output), marker) {
			t.Fatal("aggregate disclosed caller text")
		}
	}
}
