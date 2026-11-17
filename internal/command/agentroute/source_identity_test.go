package agentroute

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestRouteAuthorityContextsReserveExternalReportIdentity(t *testing.T) {
	for _, reportID := range []string{"route.ordinary", "proofkit.agent-route.cli-contract", "proofkit.agent-route.contract-map", "proofkit.agent-route.non-claims"} {
		for _, ready := range []bool{false, true} {
			input := structuralRouteInput("validate_requirement_source", ready)
			input["routeId"] = reportID
			envelope, exit, err := BuildEnvelope(input)
			if err != nil || (exit == 0) != ready {
				t.Fatalf("route readiness changed: exit=%d err=%v", exit, err)
			}
			wire := routeEnvelopeWire(t, envelope)
			if wire["sourceReport"].(map[string]any)["reportId"] != reportID {
				t.Fatal("external report identity was rewritten")
			}
			contexts := map[string]string{}
			for _, raw := range wire["contextRefs"].([]any) {
				ref := raw.(map[string]any)
				id := ref["refId"].(string)
				if id == reportID {
					t.Fatal("external report identity also resolves to a different local context")
				}
				contexts[id] = ref["path"].(string)
			}
			for id, path := range map[string]string{
				"proofkit.agent-route.cli-contract": "proofkit/cli-contract.v2.json",
				"proofkit.agent-route.contract-map": "docs/proofkit-contract-map.md",
				"proofkit.agent-route.non-claims":   "NON_CLAIMS.md",
			} {
				if id == reportID {
					id += ".local"
				}
				if contexts[id] != path {
					t.Fatal("authority target was lost or ordinary context identity changed")
				}
			}
			for _, raw := range wire["routeQuestions"].([]any) {
				refs := raw.(map[string]any)["evidenceRefs"].([]any)
				if len(refs) != 1 || refs[0] != reportID {
					t.Fatal("source-report question lost its unambiguous citation")
				}
			}
			if err := schemacheck.Validate(FullEnvelopeStructure(), envelope); err != nil {
				t.Fatal(err)
			}
		}
	}
}
