package selectivegateevidence

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func AgentEnvelope(result Result) map[string]any {
	sourceHash := stableHash(result.Report.JSONValue())
	sourceContextRef := "proofkit.agent.context.selective-evidence.001"
	allCommands := evidenceCommandRefs(result)
	commands := allCommands
	if len(commands) > itemLimit {
		commands = commands[:itemLimit]
	}
	commandIDs := []any{}
	for _, command := range commands {
		commandIDs = append(commandIDs, command["commandId"])
	}
	commandIDs = sortedAnyStrings(commandIDs)
	commandIDSet := map[string]struct{}{}
	for _, id := range commandIDs {
		if text, ok := id.(string); ok {
			commandIDSet[text] = struct{}{}
		}
	}
	allReceipts := evidenceReceiptRefs(result, commandIDSet, sourceContextRef)
	receiptRefs := allReceipts
	if len(receiptRefs) > itemLimit {
		receiptRefs = receiptRefs[:itemLimit]
	}
	contextRefs := []map[string]any{
		{"kind": "evidence", "nonClaim": "The hash identifies this evidence report payload only and does not prove freshness.", "owner": "consumer_repository", "purpose": "Stable hash of the caller-provided selective gate evidence report.", "ref": sourceHash, "refId": sourceContextRef, "role": "evidence"},
		{"kind": "evidence", "nonClaim": "The plan hash does not prove command execution or receipt freshness.", "owner": "consumer_repository", "purpose": "Stable hash of the selective gate plan used by this evidence report.", "ref": result.PlanHash, "refId": "proofkit.agent.context.selective-evidence.plan", "role": "generated_lookup"},
	}
	blocked := []map[string]any{}
	for index, receipt := range result.BlockedReceipts {
		blocked = append(blocked, map[string]any{
			"description":    fmt.Sprintf("Blocked receipt for %s must be resolved by caller-owned execution policy.", describeKey(receipt.commandKey)),
			"evidenceRefs":   []any{sourceContextRef, receipt.EvidenceRef},
			"nonClaim":       "Blocked receipt preconditions are caller-owned and are not resolved by proofkit.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("proofkit.agent.blocked-precondition.selective-evidence.blocked-receipt.%03d", index+1),
		})
	}
	for index, failure := range result.ProducerAdmissionFailures {
		blocked = append(blocked, map[string]any{
			"description":    failure,
			"evidenceRefs":   []any{sourceContextRef},
			"nonClaim":       "Producer-admission failures are metadata consistency blockers, not CI authentication results.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("proofkit.agent.blocked-precondition.selective-evidence.producer-admission.%03d", index+1),
		})
	}
	omitted := evidenceOmissions(len(allCommands)-len(commands), len(allReceipts)-len(receiptRefs), []any{sourceContextRef})
	retryIDs := retryCommandIDs(commandIDs, result)
	escalation := "Caller should resolve listed selective evidence gaps before treating the scope as proven."
	fanout := "bounded"
	if len(omitted) > 0 {
		escalation = "Caller must inspect the full selective evidence report or run a wider/full caller-owned gate."
		fanout = "wide"
	}
	verifyEvidence := retryIDs
	if len(verifyEvidence) == 0 {
		verifyEvidence = refIDs(contextRefs)
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: "proofkit.selective-gate-evidence.agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Selective gate evidence identity does not prove receipt freshness or caller approval.",
			"reportId":    result.Report.ReportID,
			"reportKind":  result.Report.ReportKind,
			"stableHash":  sourceHash,
			"state":       result.Report.State,
		},
		Bounds: map[string]any{
			"escalation":      escalation,
			"fanout":          fanout,
			"maxActionItems":  2,
			"maxCommandRefs":  len(commands),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  len(receiptRefs),
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds describe emitted item counts only and do not prove tokenizer-specific budget or proof completeness.",
			"omittedCount":    omittedCount(omitted),
		},
		ContextRefs: contextRefs,
		RouteQuestions: []map[string]any{
			question("proofkit.agent.question.what-changed", "what changed", refIDs(contextRefs), "Selective evidence reports do not prove changed-path completeness."),
			question("proofkit.agent.question.what-proves-it", "what proves it", receiptOrCommandRefs(receiptRefs, commandIDs), "Receipt refs are caller-provided evidence metadata, not freshness or CI authenticity proof."),
			question("proofkit.agent.question.who-owns-it", "who owns it", refIDs(contextRefs), "The consuming repository owns command execution, receipt production, and policy decisions."),
		},
		ClarificationQuestion: producerClarifications(result.ProducerAdmissionFailures, sourceContextRef),
		ActionPlan: []map[string]any{
			{
				"commandIds":   []any{},
				"evidenceRefs": sortedAnyStrings(refIDs(contextRefs)),
				"instruction":  "Inspect the selective evidence report gaps before editing proof or CI policy.",
				"nonClaims":    sortedAnyStrings([]any{"Route guidance does not prove evidence freshness.", "Route guidance does not approve repository edits."}),
				"owner":        "consumer_repository",
				"phase":        "route",
				"rationale":    "Evidence failures classify missing, failed, not-run, blocked, unexpected, duplicate, and producer-admission states.",
				"stepId":       "proofkit.agent.selective-gate-evidence.route",
			},
			{
				"commandIds":   retryIDs,
				"evidenceRefs": sortedAnyStrings(verifyEvidence),
				"instruction":  verifyInstruction(retryIDs),
				"nonClaims":    sortedAnyStrings([]any{"Verify guidance does not execute commands.", "Verify guidance does not prove receipt freshness, producer admission, or merge approval."}),
				"owner":        "consumer_repository",
				"phase":        "verify",
				"rationale":    "Proofkit can identify evidence gaps, but native execution and receipt production remain outside proofkit.",
				"stepId":       "proofkit.agent.selective-gate-evidence.verify",
			},
		},
		Commands:             commands,
		BlockedPreconditions: blocked,
		Omitted:              omitted,
		ReceiptRefs:          receiptRefs,
		NonClaims: []string{
			"Selective gate evidence envelopes do not approve merge, rollout, or repository policy.",
			"Selective gate evidence envelopes do not authenticate receipt producers.",
			"Selective gate evidence envelopes do not execute native witnesses.",
			"Selective gate evidence envelopes do not prove receipt freshness.",
		},
	})
}

func evidenceCommandRefs(result Result) []map[string]any {
	byID := map[string]commandKey{}
	for _, item := range result.MissingReceipts {
		byID[item.ID] = item
	}
	for _, item := range result.FailedReceipts {
		if _, ok := byID[item.ID]; !ok {
			byID[item.ID] = item.commandKey
		}
	}
	for _, item := range result.NotRunReceipts {
		if _, ok := byID[item.ID]; !ok {
			byID[item.ID] = item.commandKey
		}
	}
	for _, item := range result.BlockedReceipts {
		if _, ok := byID[item.ID]; !ok {
			byID[item.ID] = item.commandKey
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	resultRefs := []map[string]any{}
	for _, id := range ids {
		item := byID[id]
		resultRefs = append(resultRefs, map[string]any{"command": item.Command, "commandId": item.ID, "nonClaim": "Proofkit lists this command but does not execute it or prove it passed.", "owner": "consumer_repository", "purpose": "Caller-owned command with selective evidence gap: " + describeKey(item)})
	}
	return resultRefs
}

func evidenceReceiptRefs(result Result, commandIDs map[string]struct{}, sourceContextRef string) []map[string]any {
	refs := []map[string]any{}
	for index, receipt := range result.MissingReceipts {
		if _, ok := commandIDs[receipt.ID]; !ok {
			continue
		}
		refs = append(refs, map[string]any{"commandId": receipt.ID, "evidenceRefs": []any{sourceContextRef}, "kind": "required_receipt_class", "nonClaim": "Required receipt classes describe missing caller-owned evidence; they are not receipt artifacts.", "owner": "consumer_repository", "producer": nil, "producerAdmission": "required", "receiptRefId": fmt.Sprintf("proofkit.agent.receipt.required.selective-evidence.%03d", index+1), "ref": receipt.ID})
	}
	items := append(append([]receiptSummary{}, result.FailedReceipts...), result.NotRunReceipts...)
	items = append(items, result.BlockedReceipts...)
	for index, receipt := range items {
		if _, ok := commandIDs[receipt.ID]; !ok {
			continue
		}
		refs = append(refs, map[string]any{"commandId": receipt.ID, "evidenceRefs": []any{sourceContextRef, receipt.EvidenceRef}, "kind": "receipt_artifact", "nonClaim": "Receipt artifact refs are caller-provided metadata and do not prove freshness or producer admission.", "owner": "consumer_repository", "producer": nil, "producerAdmission": "unverified", "receiptRefId": fmt.Sprintf("proofkit.agent.receipt.artifact.selective-evidence.%03d", index+1), "ref": receipt.EvidenceRef})
	}
	return refs
}

func producerClarifications(failures []string, sourceContextRef string) []map[string]any {
	result := []map[string]any{}
	for index, failure := range failures {
		result = append(result, map[string]any{"askWhen": "Selective evidence has producer-admission metadata failures.", "blocking": true, "evidenceRefs": []any{sourceContextRef}, "expectedAnswerKind": "owner_decision", "nonClaim": "The question does not authenticate a producer or approve a receipt.", "owner": "consumer_repository", "question": fmt.Sprintf("Which caller-owned producer policy or receipt metadata should resolve this failure: %s?", failure), "questionId": fmt.Sprintf("proofkit.agent.clarify.selective-evidence.producer-admission.%03d", index+1)})
	}
	return result
}

func evidenceOmissions(commandOmitted int, receiptOmitted int, evidenceRefs []any) []map[string]any {
	result := []map[string]any{}
	if commandOmitted > 0 {
		result = append(result, map[string]any{"evidenceRefs": evidenceRefs, "escalation": "Inspect the full selective evidence report or run a wider/full caller-owned gate.", "nonClaim": "Omitted command counts are not pass evidence for omitted commands.", "omissionId": "proofkit.agent.omission.selective-evidence-commands", "omittedCount": commandOmitted, "reason": "selective evidence command gaps exceeded bounded envelope command limit"})
	}
	if receiptOmitted > 0 {
		result = append(result, map[string]any{"evidenceRefs": evidenceRefs, "escalation": "Inspect the full selective evidence report before treating receipt coverage as complete.", "nonClaim": "Omitted receipt counts do not summarize hidden receipt states semantically.", "omissionId": "proofkit.agent.omission.selective-evidence-receipts", "omittedCount": receiptOmitted, "reason": "selective evidence receipt refs exceeded bounded envelope receipt limit"})
	}
	return result
}

func retryCommandIDs(commandIDs []any, result Result) []any {
	targets := map[string]struct{}{}
	for _, item := range result.MissingReceipts {
		targets[item.ID] = struct{}{}
	}
	for _, item := range result.FailedReceipts {
		targets[item.ID] = struct{}{}
	}
	for _, item := range result.NotRunReceipts {
		targets[item.ID] = struct{}{}
	}
	resultIDs := []any{}
	for _, id := range commandIDs {
		if text, ok := id.(string); ok {
			if _, wanted := targets[text]; wanted {
				resultIDs = append(resultIDs, text)
			}
		}
	}
	return sortedAnyStrings(resultIDs)
}

func verifyInstruction(retryIDs []any) string {
	if len(retryIDs) > 0 {
		return "Run or repair the listed caller-owned commands, then provide fresh admitted receipts."
	}
	return "Resolve non-command evidence blockers before treating this scope as proven."
}

func receiptOrCommandRefs(receipts []map[string]any, commands []any) []any {
	if len(receipts) == 0 {
		return sortedAnyStrings(commands)
	}
	result := []any{}
	for _, receipt := range receipts {
		result = append(result, receipt["receiptRefId"])
	}
	return sortedAnyStrings(result)
}

func refIDs(refs []map[string]any) []any {
	result := make([]any, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ref["refId"])
	}
	return sortedAnyStrings(result)
}

func question(id string, text string, evidenceRefs []any, nonClaim string) map[string]any {
	return map[string]any{"evidenceRefs": sortedAnyStrings(evidenceRefs), "nonClaim": nonClaim, "question": text, "questionId": id}
}

func sortedAnyStrings(values []any) []any {
	result := append([]any{}, values...)
	sort.Slice(result, func(left int, right int) bool {
		leftValue, _ := result[left].(string)
		rightValue, _ := result[right].(string)
		return leftValue < rightValue
	})
	return result
}

func omittedCount(values []map[string]any) int {
	count := 0
	for _, value := range values {
		if item, ok := value["omittedCount"].(int); ok {
			count += item
		}
	}
	return count
}
