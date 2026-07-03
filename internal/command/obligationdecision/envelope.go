package obligationdecision

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

const maxEnvelopeDecisions = 20

func AgentEnvelope(result Result) map[string]any {
	actionable := actionableDecisions(result.Decisions)
	emitted := actionable
	omittedCount := 0
	if len(emitted) > maxEnvelopeDecisions {
		omittedCount = len(emitted) - maxEnvelopeDecisions
		emitted = emitted[:maxEnvelopeDecisions]
	}
	contextRefs := []map[string]any{}
	receiptRefs := []map[string]any{}
	clarifications := []map[string]any{}
	blocked := []map[string]any{}
	actions := []map[string]any{}
	for index, decision := range emitted {
		number := index + 1
		requirementRefID := fmt.Sprintf("proofkit.agent.context.obligation-decision.%03d.requirement", number)
		routeRefID := fmt.Sprintf("proofkit.agent.context.obligation-decision.%03d.proof-route", number)
		contextRefs = append(contextRefs,
			contextRef(requirementRefID, "requirement", decision.RequirementID, decision.Owner, "Requirement owning this obligation decision."),
			contextRef(routeRefID, "proof-route", decision.ProofRouteRef, decision.Owner, "Proof route attached to this obligation decision."),
		)
		evidenceRefIDs := []any{requirementRefID, routeRefID}
		for evidenceIndex, evidenceRef := range decision.EvidenceRefs {
			refID := fmt.Sprintf("proofkit.agent.context.obligation-decision.%03d.evidence.%03d", number, evidenceIndex+1)
			contextRefs = append(contextRefs, contextRef(refID, "evidence", evidenceRef, decision.Owner, "Caller-provided evidence ref for this obligation."))
			evidenceRefIDs = append(evidenceRefIDs, refID)
		}
		if needsReceiptRef(decision.DecisionState) {
			receiptRefID := fmt.Sprintf("proofkit.agent.receipt.obligation-decision.%03d", number)
			receiptRefs = append(receiptRefs, map[string]any{
				"evidenceRefs":  evidenceRefIDs,
				"nonClaim":      "Receipt refs route missing or invalid caller-owned receipt evidence only; they do not prove freshness or producer admission.",
				"obligationId":  decision.ObligationID,
				"owner":         decision.Owner,
				"proofRouteRef": decision.ProofRouteRef,
				"receiptClass":  decision.DecisionState,
				"receiptRefId":  receiptRefID,
				"requirementId": decision.RequirementID,
				"selectedState": decision.DecisionState,
			})
			evidenceRefIDs = append(evidenceRefIDs, receiptRefID)
		}
		if needsClarification(decision.DecisionState) {
			clarifications = append(clarifications, map[string]any{
				"askWhen":            "The obligation decision state requires caller-owned policy or environment context.",
				"blocking":           decision.BlocksProofSatisfaction,
				"evidenceRefs":       evidenceRefIDs,
				"expectedAnswerKind": clarificationKind(decision.DecisionState),
				"nonClaim":           "Clarification questions do not approve merge or prove the missing caller-owned fact.",
				"owner":              decision.Owner,
				"question":           clarificationQuestion(decision.DecisionState),
				"questionId":         fmt.Sprintf("proofkit.agent.clarify.obligation-decision.%03d", number),
			})
		}
		if decision.BlocksProofSatisfaction || needsBlockedPrecondition(decision.DecisionState) {
			blocked = append(blocked, map[string]any{
				"description":    fmt.Sprintf("Obligation %s selected %s.", decision.ObligationID, decision.DecisionState),
				"evidenceRefs":   evidenceRefIDs,
				"nonClaim":       "Blocked preconditions route caller-owned proof state and are not resolved by proofkit.",
				"owner":          decision.Owner,
				"preconditionId": fmt.Sprintf("proofkit.agent.blocked-precondition.obligation-decision.%03d", number),
			})
		}
		actions = append(actions, map[string]any{
			"commandIds":   []any{},
			"evidenceRefs": evidenceRefIDs,
			"instruction":  actionInstruction(decision.DecisionState),
			"nonClaims":    []any{"Obligation decision guidance does not execute native witnesses or approve merge."},
			"owner":        decision.Owner,
			"phase":        actionPhase(decision.DecisionState),
			"rationale":    decision.Reason,
			"stepId":       fmt.Sprintf("proofkit.agent.obligation-decision.%03d", number),
		})
	}
	omitted := []map[string]any{}
	if omittedCount > 0 {
		omitted = append(omitted, map[string]any{
			"nonClaim":     "Omitted obligation decisions require the caller to inspect the full source report or run a wider gate.",
			"omissionId":   "proofkit.agent.omitted.obligation-decision",
			"omittedCount": omittedCount,
			"owner":        "consumer_repository",
			"reason":       "bounded envelope decision limit reached",
		})
	}
	fanout := "bounded"
	escalation := "Caller should inspect the source obligation-decision report before treating proof obligations as complete."
	if len(result.BlockingUnsatisfiedObligationIDs) > 0 || omittedCount > 0 {
		fanout = "full-gate"
		escalation = "Caller must resolve blocking decisions, inspect omitted decisions, or run a wider/full caller-owned gate."
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: "proofkit.obligation-decision.agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Obligation-decision identity does not prove receipt freshness, producer admission, or merge approval.",
			"reportId":    result.Report.ReportID,
			"reportKind":  result.Report.ReportKind,
			"stableHash":  nil,
			"state":       result.Report.State,
		},
		Bounds: map[string]any{
			"escalation":      escalation,
			"fanout":          fanout,
			"maxActionItems":  maxEnvelopeDecisions,
			"maxCommandRefs":  0,
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": 1,
			"maxReceiptRefs":  len(receiptRefs),
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds describe emitted item counts only and do not prove tokenizer-specific budget or proof completeness.",
			"omittedCount":    omittedCount,
		},
		ContextRefs:           contextRefs,
		RouteQuestions:        routeQuestions(),
		ClarificationQuestion: clarifications,
		ActionPlan:            actions,
		Commands:              []map[string]any{},
		BlockedPreconditions:  blocked,
		Omitted:               omitted,
		ReceiptRefs:           receiptRefs,
		NonClaims: []string{
			"Obligation decision envelopes do not authenticate producers.",
			"Obligation decision envelopes do not compute receipt freshness.",
			"Obligation decision envelopes do not execute native witnesses.",
			"Obligation decision envelopes do not approve merge, release, rollout, or repository policy.",
		},
	})
}

func actionableDecisions(decisions []obligationDecision) []obligationDecision {
	result := []obligationDecision{}
	for _, decision := range decisions {
		if decision.DecisionState != "satisfied" && decision.DecisionState != "not_applicable" {
			result = append(result, decision)
		}
	}
	return result
}

func contextRef(refID string, kind string, ref string, owner string, purpose string) map[string]any {
	return map[string]any{
		"kind":     kind,
		"nonClaim": "Context refs route caller-owned obligation decision facts only and do not prove freshness.",
		"owner":    owner,
		"purpose":  purpose,
		"ref":      ref,
		"refId":    refID,
		"role":     kind,
	}
}

func routeQuestions() []map[string]any {
	return []map[string]any{
		{"evidenceRefs": []any{}, "nonClaim": "Obligation decisions do not discover changed files.", "question": "what changed", "questionId": "proofkit.agent.question.what-changed"},
		{"evidenceRefs": []any{}, "nonClaim": "Obligation decisions classify supplied evidence state only.", "question": "what proves it", "questionId": "proofkit.agent.question.what-proves-it"},
		{"evidenceRefs": []any{}, "nonClaim": "The consuming repository owns proof policy and merge decisions.", "question": "who owns it", "questionId": "proofkit.agent.question.who-owns-it"},
	}
}

func needsReceiptRef(state string) bool {
	return state == "missing_receipt" || state == "invalid_receipt" || state == "stale_receipt"
}

func needsClarification(state string) bool {
	switch state {
	case "unknown_scope", "unavailable_live", "deferred_admitted", "advisory_skipped":
		return true
	default:
		return false
	}
}

func needsBlockedPrecondition(state string) bool {
	return state == "blocked_missing_precondition" || state == "unknown_scope" || state == "unavailable_live"
}

func clarificationKind(state string) string {
	switch state {
	case "unknown_scope":
		return "scope_decision"
	case "unavailable_live":
		return "live_environment_decision"
	case "deferred_admitted":
		return "deferral_owner_decision"
	default:
		return "advisory_owner_decision"
	}
}

func clarificationQuestion(state string) string {
	switch state {
	case "unknown_scope":
		return "Which caller-owned scope decision or full gate resolves this unknown scope?"
	case "unavailable_live":
		return "Which caller-owned live environment precondition is required before this evidence can be trusted?"
	case "deferred_admitted":
		return "Which owner and expiry keep this deferred obligation admissible?"
	default:
		return "Which owner decided this advisory obligation may be skipped for the current gate?"
	}
}

func actionInstruction(state string) string {
	switch state {
	case "missing_receipt":
		return "Collect or link the caller-owned receipt required for this proof route."
	case "invalid_receipt", "invalid_producer", "stale_receipt":
		return "Repair or refresh the caller-owned proof evidence before treating this obligation as satisfied."
	case "failed":
		return "Fix the failing caller-owned proof or run the appropriate wider gate."
	case "blocked_missing_precondition", "unknown_scope", "unavailable_live":
		return "Resolve the caller-owned precondition or escalate to the full owner gate."
	case "deferred_admitted", "advisory_skipped":
		return "Verify the caller-owned owner, expiry, and risk acceptance for this non-blocking decision."
	default:
		return "Inspect this caller-owned obligation decision before treating proof coverage as complete."
	}
}

func actionPhase(state string) string {
	switch state {
	case "missing_receipt", "invalid_receipt", "invalid_producer", "stale_receipt", "failed":
		return "verify"
	case "blocked_missing_precondition", "unknown_scope", "unavailable_live":
		return "route"
	default:
		return "review"
	}
}
