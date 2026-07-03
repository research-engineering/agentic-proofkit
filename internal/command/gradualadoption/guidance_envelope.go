package gradualadoption

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func guidanceEnvelope(result guidanceResult) map[string]any {
	commandRefs := []map[string]any{}
	commandIDByText := map[string]string{}
	for index, command := range stringArrayFromMap(result.Guidance, "commands") {
		commandID := fmt.Sprintf("proofkit.agent.command.%03d", index+1)
		commandIDByText[command] = commandID
		commandRefs = append(commandRefs, map[string]any{
			"command":   command,
			"commandId": commandID,
			"nonClaim":  "Proofkit reports this command but does not execute it or prove it passed.",
			"owner":     "consumer_repository",
			"purpose":   "Caller-owned native witness command reported for agent routing.",
		})
	}
	ownerRoute := result.Guidance["ownerRoute"].(map[string]any)
	contextRefs := []map[string]any{}
	contextRefs = append(contextRefs, pathContextRefs(stringArrayFromMap(ownerRoute, "evidencePaths"), "evidence", "evidence", "Caller-owned evidence artifact route.")...)
	contextRefs = append(contextRefs, pathContextRefs(stringArrayFromMap(ownerRoute, "proofBindingPaths"), "proof-binding", "proof_binding", "Caller-owned requirement-to-witness binding route.")...)
	contextRefs = append(contextRefs, pathContextRefs(stringArrayFromMap(ownerRoute, "specPaths"), "spec", "spec_source", "Caller-owned specification route.")...)
	contextRefs = append(contextRefs, ruleContextRefs(stringArrayFromMap(result.Guidance, "sourceFailedRuleIds"), "source-failure", "Source report failure rule requiring caller-owned inspection.")...)
	contextRefs = append(contextRefs, ruleContextRefs(stringArrayFromMap(result.Guidance, "sourceWarningRuleIds"), "source-warning", "Source report warning rule requiring caller-owned inspection.")...)
	contextRefs = append(contextRefs, ruleContextRefs(stringArrayFromMap(result.Guidance, "proofBindingsMissing"), "missing-proof-binding", "Caller-reported missing proof binding obligation.")...)
	contextRefs = append(contextRefs, candidateBoundaryContextRefs(anyArrayFromMap(result.Guidance, "candidateBoundaries"))...)
	actionPlan := []map[string]any{}
	for _, rawAction := range result.Guidance["agentActionPlan"].([]any) {
		action := rawAction.(map[string]any)
		commandIDs := []string{}
		for _, command := range stringArrayFromMap(action, "commands") {
			commandID, ok := commandIDByText[command]
			if !ok {
				commandID = command
			}
			commandIDs = append(commandIDs, commandID)
		}
		actionPlan = append(actionPlan, map[string]any{
			"commandIds":   admit.StringSliceToAny(commandIDs),
			"evidenceRefs": action["evidenceRefs"],
			"instruction":  action["instruction"],
			"nonClaims":    action["nonClaims"],
			"owner":        action["owner"],
			"phase":        action["phase"],
			"rationale":    envelopeActionRationale(action["phase"].(string)),
			"stepId":       action["stepId"],
		})
	}
	blocked := []map[string]any{}
	for index, precondition := range stringArrayFromMap(result.Guidance, "blockedPreconditions") {
		blocked = append(blocked, map[string]any{
			"description":    precondition,
			"evidenceRefs":   []any{precondition},
			"nonClaim":       "Blocked preconditions are caller-owned and are not resolved by proofkit.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("proofkit.agent.blocked-precondition.%03d", index+1),
		})
	}
	contextRefIDs := envelopeMapValues(contextRefs, "refId")
	commandIDs := envelopeMapValues(commandRefs, "commandId")
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: fmt.Sprintf("%s.agent-envelope", result.Record.ReportID),
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Source report identity does not prove native witness execution, freshness, or caller approval.",
			"reportId":    result.Record.ReportID,
			"reportKind":  result.Record.ReportKind,
			"stableHash":  nil,
			"state":       result.Record.State,
		},
		Bounds: map[string]any{
			"escalation":      "Caller must run a wider caller-owned proof plan when these refs do not cover the changed repository scope.",
			"fanout":          "bounded",
			"maxActionItems":  len(actionPlan),
			"maxCommandRefs":  len(commandRefs),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds cover generated envelope item counts only; they do not prove tokenizer-specific budget or proof completeness.",
			"omittedCount":    0,
		},
		ContextRefs: contextRefs,
		RouteQuestions: []map[string]any{
			{"evidenceRefs": admit.StringSliceToAny(contextRefIDs), "nonClaim": "This question routes context only; it does not decide repository truth.", "question": "what changed", "questionId": "proofkit.agent.question.what-changed"},
			{"evidenceRefs": map[bool][]any{true: admit.StringSliceToAny(commandIDs), false: admit.StringSliceToAny(contextRefIDs)}[len(commandIDs) > 0], "nonClaim": "Command references are planned caller-owned witnesses, not pass evidence.", "question": "what proves it", "questionId": "proofkit.agent.question.what-proves-it"},
			{"evidenceRefs": admit.StringSliceToAny(contextRefIDs), "nonClaim": "Ownership remains in the consuming repository.", "question": "who owns it", "questionId": "proofkit.agent.question.who-owns-it"},
		},
		ClarificationQuestion: guidanceClarifications(result.Guidance),
		ActionPlan:            actionPlan,
		Commands:              commandRefs,
		BlockedPreconditions:  blocked,
		Omitted:               []map[string]any{},
		ReceiptRefs:           []map[string]any{},
		NonClaims:             stringArrayFromMap(result.Guidance, "nonClaims"),
	})
}

func candidateBoundaryContextRefs(candidates []any) []map[string]any {
	refs := []map[string]any{}
	for index, raw := range candidates {
		candidate := raw.(map[string]any)
		refs = append(refs, map[string]any{
			"kind":     "candidate-boundary",
			"nonClaim": candidateBoundaryNonClaim,
			"owner":    "consumer_repository",
			"purpose":  "Advisory candidate semantic boundary requiring owner admission.",
			"ref":      candidate["boundaryId"],
			"refId":    fmt.Sprintf("proofkit.agent.context.candidate-boundary.%03d", index+1),
			"role":     "candidate_boundary",
		})
	}
	return refs
}

func pathContextRefs(paths []string, prefix string, role string, purpose string) []map[string]any {
	refs := make([]map[string]any, 0, len(paths))
	for index, path := range paths {
		refs = append(refs, map[string]any{
			"kind":     "path",
			"nonClaim": "Context refs route agent loading only and do not prove freshness or correctness.",
			"owner":    "consumer_repository",
			"purpose":  purpose,
			"ref":      path,
			"refId":    fmt.Sprintf("proofkit.agent.context.%s.%03d", prefix, index+1),
			"role":     role,
		})
	}
	return refs
}

func ruleContextRefs(ruleIDs []string, prefix string, purpose string) []map[string]any {
	refs := make([]map[string]any, 0, len(ruleIDs))
	for index, ruleID := range ruleIDs {
		refs = append(refs, map[string]any{
			"kind":     "rule",
			"nonClaim": "Rule refs route caller-owned inspection only and do not prove remediation.",
			"owner":    "consumer_repository",
			"purpose":  purpose,
			"ref":      ruleID,
			"refId":    fmt.Sprintf("proofkit.agent.context.%s.%03d", prefix, index+1),
			"role":     "rule_reference",
		})
	}
	return refs
}

func guidanceClarifications(guidance map[string]any) []map[string]any {
	questions := []map[string]any{}
	mode := guidance["guidanceMode"].(string)
	blocking := adoptionmode.IsEnforcing(mode)
	for index, binding := range stringArrayFromMap(guidance, "proofBindingsMissing") {
		questions = append(questions, map[string]any{
			"askWhen":            "A requirement or source failure has no caller-owned proof binding route.",
			"blocking":           blocking,
			"evidenceRefs":       []any{binding},
			"expectedAnswerKind": "missing_witness",
			"nonClaim":           "The question does not create or approve a proof binding.",
			"owner":              "consumer_repository",
			"question":           fmt.Sprintf("Which caller-owned witness should bind %s?", binding),
			"questionId":         fmt.Sprintf("proofkit.agent.clarify.missing-proof-binding.%03d", index+1),
		})
	}
	for index, precondition := range stringArrayFromMap(guidance, "blockedPreconditions") {
		questions = append(questions, map[string]any{
			"askWhen":            "A caller-owned external precondition blocks reliable proof routing.",
			"blocking":           true,
			"evidenceRefs":       []any{precondition},
			"expectedAnswerKind": "blocked_external_input",
			"nonClaim":           "The question does not prove that the external precondition is satisfied.",
			"owner":              "consumer_repository",
			"question":           fmt.Sprintf("What caller-owned evidence resolves this blocked precondition: %s?", precondition),
			"questionId":         fmt.Sprintf("proofkit.agent.clarify.blocked-precondition.%03d", index+1),
		})
	}
	for candidateIndex, raw := range anyArrayFromMap(guidance, "candidateBoundaries") {
		candidate := raw.(map[string]any)
		for questionIndex, question := range stringArrayFromMap(candidate, "ownerQuestions") {
			questions = append(questions, map[string]any{
				"askWhen":            "A candidate boundary is advisory and cannot be promoted without owner review.",
				"blocking":           true,
				"evidenceRefs":       append([]any{candidate["boundaryId"]}, admit.StringSliceToAny(stringArrayFromMap(candidate, "affectedPaths"))...),
				"expectedAnswerKind": "owner_boundary_decision",
				"nonClaim":           "The question does not admit candidate boundaries as repository semantics.",
				"owner":              "consumer_repository",
				"question":           question,
				"questionId":         fmt.Sprintf("proofkit.agent.clarify.candidate-boundary.%03d.%03d", candidateIndex+1, questionIndex+1),
			})
		}
	}
	return questions
}
