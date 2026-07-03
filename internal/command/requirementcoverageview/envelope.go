package requirementcoverageview

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func agentEnvelope(view map[string]any) map[string]any {
	state := stringValue(view["state"])
	failures := stringArray(view["failures"])
	commands := []map[string]any{}
	if state == "failed" {
		commands = append(commands, map[string]any{
			"argv":      []any{"agentic-proofkit", "requirement-coverage-view", "--input", "<coverage-input.json>"},
			"commandId": "proofkit.requirement-coverage-view.rerun",
			"nonClaim":  "Command refs are suggestions only; the consumer repository owns paths and execution.",
			"reason":    "Rebuild the coverage view after repairing caller-owned coverage input.",
		})
	}
	blockers := []map[string]any{}
	for index, failure := range failures {
		if index >= 12 {
			break
		}
		blockers = append(blockers, map[string]any{
			"description":    failure,
			"evidenceRefs":   []any{"proofkit.requirement-coverage-view.failures"},
			"nonClaim":       "Coverage blockers are derived from caller-owned input and do not execute native tests.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("proofkit.coverage.blocker.%03d", index+1),
		})
	}
	return agentenvelope.Build(agentenvelope.Input{
		ActionPlan: []map[string]any{
			{
				"commandIds":   []any{},
				"evidenceRefs": []any{"proofkit.requirement-coverage-view.summary"},
				"instruction":  "Use the coverage view to identify requirements, commands, and test surfaces lacking semantic falsifiers.",
				"nonClaims":    []any{"This action does not approve merge or create tests."},
				"owner":        "consumer_repository",
				"phase":        "review",
				"rationale":    "Semantic coverage cannot be inferred from route bindings alone.",
				"stepId":       "proofkit.coverage.review-gaps",
			},
		},
		BlockedPreconditions: blockers,
		Bounds: map[string]any{
			"escalation":      "Run a full consumer-owned gate when the coverage input is incomplete or the envelope is truncated.",
			"fanout":          "bounded",
			"maxActionItems":  1,
			"maxCommandRefs":  len(commands),
			"maxContextRefs":  5,
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  2400,
			"nonClaim":        "Bounds describe emitted guidance only and do not prove tokenizer-specific coverage.",
			"omittedCount":    max(0, len(failures)-len(blockers)),
		},
		Commands: commands,
		ContextRefs: []map[string]any{
			contextRef("proofkit.requirement-coverage-view.summary", "/guidanceSummary", "Coverage guidance summary."),
			contextRef("proofkit.requirement-coverage-view.failures", "/failures", "Fail-closed coverage diagnostics."),
			contextRef("proofkit.requirement-coverage-view.owner-invariants", "/ownerInvariantCoverage", "Per-owner-invariant coverage states."),
			contextRef("proofkit.requirement-coverage-view.requirements", "/requirementCoverage", "Per-requirement coverage states."),
			contextRef("proofkit.requirement-coverage-view.commands", "/commandCoverage", "Per-command semantic falsifier states."),
		},
		EnvelopeID: "proofkit.requirement-coverage-view.agent-envelope",
		NonClaims: []string{
			"Requirement coverage envelopes do not scan repositories.",
			"Requirement coverage envelopes do not execute tests or approve merge.",
		},
		Omitted:     []map[string]any{},
		ReceiptRefs: []map[string]any{},
		RouteQuestions: []map[string]any{
			{"evidenceRefs": []any{"proofkit.requirement-coverage-view.requirements"}, "nonClaim": "Coverage view routes supplied requirement facts only.", "question": "what changed", "questionId": "proofkit.coverage.question.what-changed"},
			{"evidenceRefs": []any{"proofkit.requirement-coverage-view.failures"}, "nonClaim": "Coverage view classifies supplied proof/test inventory only.", "question": "what proves it", "questionId": "proofkit.coverage.question.what-proves-it"},
			{"evidenceRefs": []any{"proofkit.requirement-coverage-view.summary"}, "nonClaim": "The consuming repository owns semantic truth and native tests.", "question": "who owns it", "questionId": "proofkit.coverage.question.who-owns-it"},
		},
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Coverage view identity does not prove freshness or native witness execution.",
			"reportId":    stringValue(view["viewInputId"]),
			"reportKind":  "proofkit.requirement-coverage-view",
			"state":       state,
		},
	})
}
func contextRef(refID string, pointer string, purpose string) map[string]any {
	return map[string]any{
		"kind":     "json-pointer",
		"nonClaim": "Context refs point into a derived coverage view and do not prove source freshness.",
		"owner":    "consumer_repository",
		"purpose":  purpose,
		"ref":      pointer,
		"refId":    refID,
		"role":     "supporting",
	}
}
