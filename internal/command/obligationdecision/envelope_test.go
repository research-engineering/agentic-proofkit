package obligationdecision

import (
	"encoding/json"
	"testing"
)

func TestAgentEnvelopeRoutesAdvisoryReceiptsAndBlockingClarifications(t *testing.T) {
	result, err := Build(map[string]any{
		"schemaVersion": json.Number("1"),
		"decisionId":    "proofkit.test.decision",
		"nonClaims":     []any{"Synthetic obligation input does not approve merge."},
		"obligations": []any{
			map[string]any{
				"candidateStates": []any{"missing_receipt"},
				"evidenceRefs":    []any{"artifacts/advisory.json"},
				"nonClaims":       []any{"Advisory receipt is caller-owned."},
				"obligationClass": "advisory",
				"obligationId":    "proofkit.obligation.advisory",
				"owner":           "proofkit.test",
				"proofRouteRef":   "proofkit.route.advisory",
				"reason":          "Advisory receipt is absent.",
				"requirementId":   "REQ-PROOFKIT-ADVISORY",
			},
			map[string]any{
				"candidateStates": []any{"unknown_scope"},
				"evidenceRefs":    []any{"artifacts/blocking.json"},
				"nonClaims":       []any{"Scope is caller-owned."},
				"obligationClass": "blocking",
				"obligationId":    "proofkit.obligation.blocking",
				"owner":           "proofkit.test",
				"proofRouteRef":   "proofkit.route.blocking",
				"reason":          "Changed scope is unknown.",
				"requirementId":   "REQ-PROOFKIT-BLOCKING",
			},
		},
	})
	if err != nil {
		t.Fatalf("build obligation decision: %v", err)
	}
	envelope := AgentEnvelope(result)
	if envelope["schemaVersion"] != 1 {
		t.Fatalf("unexpected envelope schema: %#v", envelope["schemaVersion"])
	}
	if envelope["sourceReport"].(map[string]any)["state"] != "failed" {
		t.Fatalf("source report state must remain failed for blocking unknown scope: %#v", envelope["sourceReport"])
	}
	if got := len(envelope["receiptRefs"].([]any)); got != 1 {
		t.Fatalf("advisory missing receipt must still be routed, got %d receipt refs", got)
	}
	if got := len(envelope["blockedPreconditions"].([]any)); got != 1 {
		t.Fatalf("blocking unknown scope must emit one blocked precondition, got %d", got)
	}
	if got := len(envelope["clarificationQuestions"].([]any)); got != 1 {
		t.Fatalf("unknown scope must emit one clarification question, got %d", got)
	}
	if got := len(envelope["actionPlan"].([]any)); got != 2 {
		t.Fatalf("each actionable decision must emit an action, got %d", got)
	}
	if got := envelope["bounds"].(map[string]any)["fanout"]; got != "full-gate" {
		t.Fatalf("blocking unknown scope must escalate to full-gate, got %v", got)
	}
}

func TestAgentEnvelopeOmitsBeyondBoundedDecisionLimit(t *testing.T) {
	obligations := make([]any, 0, maxEnvelopeDecisions+1)
	for index := 0; index < maxEnvelopeDecisions+1; index++ {
		obligations = append(obligations, map[string]any{
			"candidateStates": []any{"missing_receipt"},
			"evidenceRefs":    []any{"artifacts/evidence.json"},
			"nonClaims":       []any{"Synthetic obligation is caller-owned."},
			"obligationClass": "advisory",
			"obligationId":    "proofkit.obligation.advisory." + letter(index),
			"owner":           "proofkit.test",
			"proofRouteRef":   "proofkit.route.advisory",
			"reason":          "Advisory receipt is absent.",
			"requirementId":   "REQ-PROOFKIT-ADVISORY-" + letter(index),
		})
	}
	result, err := Build(map[string]any{
		"schemaVersion": json.Number("1"),
		"decisionId":    "proofkit.test.decision",
		"nonClaims":     []any{"Synthetic obligation input does not approve merge."},
		"obligations":   obligations,
	})
	if err != nil {
		t.Fatalf("build obligation decision: %v", err)
	}
	envelope := AgentEnvelope(result)
	if got := len(envelope["actionPlan"].([]any)); got != maxEnvelopeDecisions {
		t.Fatalf("expected bounded action count %d, got %d", maxEnvelopeDecisions, got)
	}
	omitted := envelope["omitted"].([]any)
	if len(omitted) != 1 {
		t.Fatalf("expected capped omission summary, got %#v", omitted)
	}
	overflow := omitted[0].(map[string]any)
	if overflow["omissionId"] != "proofkit.agent-envelope.omitted.overflow" || overflow["omittedCount"] != 13 {
		t.Fatalf("expected semantic omitted proof-surface count 13, got %#v", omitted)
	}
	cost := envelope["costContract"].(map[string]any)
	if cost["omittedEdgeCount"] != 13 || cost["stopReason"] != "wide_or_full_gate_required" {
		t.Fatalf("unexpected cost contract: %#v", cost)
	}
}

func letter(index int) string {
	return string(rune('A' + index))
}
