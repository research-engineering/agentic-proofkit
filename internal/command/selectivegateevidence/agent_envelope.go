package selectivegateevidence

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

func AgentEnvelope(result Result) map[string]any {
	sourceHash := stableHash(result.Report.JSONValue())
	sourceContextRef := evidenceLocalID("proofkit.agent.context.selective-evidence.001", result)
	allCommandKeys := evidenceCommandKeys(result)
	plannedIDs := evidencePlannedCommandIDs(result)
	commands := []map[string]any{}
	commandIDsByKey := map[string]string{}
	commandIDs := []any{}
	for index, key := range allCommandKeys {
		if index == itemLimit {
			break
		}
		id := plannedIDs[keyString(key)]
		commandIDsByKey[keyString(key)] = id
		commandIDs = append(commandIDs, id)
		commands = append(commands, map[string]any{"command": key.Command, "commandId": id, "nonClaim": "Proofkit lists this command but does not execute it or prove it passed.", "owner": "consumer_repository", "purpose": "Caller-owned command with selective evidence gap: " + describeKey(key)})
	}
	commandIDs = sortedAnyStrings(commandIDs)
	receiptRefs, artifactContexts, artifactContextIDs, candidateReceiptCount := evidenceReceiptRefs(result, commandIDsByKey, sourceContextRef)
	contextRefs := []map[string]any{
		{"kind": "evidence", "nonClaim": "The hash identifies this evidence report payload only and does not prove freshness.", "owner": "consumer_repository", "purpose": "Stable hash of the caller-provided selective gate evidence report.", "ref": sourceHash, "refId": sourceContextRef, "role": "evidence"},
		{"kind": "evidence", "nonClaim": "The plan hash does not prove command execution or receipt freshness.", "owner": "consumer_repository", "purpose": "Stable hash of the selective gate plan used by this evidence report.", "ref": result.PlanHash, "refId": evidenceLocalID("proofkit.agent.context.selective-evidence.plan", result), "role": "generated_lookup"},
	}
	contextRefs = append(contextRefs, artifactContexts...)
	blocked := []map[string]any{}
	for index, receipt := range result.BlockedReceipts {
		refs := []any{sourceContextRef}
		if id, found := artifactContextIDs[receipt.EvidenceRef]; found {
			refs = append(refs, id)
		}
		blocked = append(blocked, map[string]any{
			"description":    fmt.Sprintf("Blocked receipt for %s must be resolved by caller-owned execution policy.", describeKey(receipt.commandKey)),
			"evidenceRefs":   refs,
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
	omitted := evidenceOmissions(len(allCommandKeys)-len(commands), candidateReceiptCount-len(receiptRefs), []any{sourceContextRef})
	retryIDs := retryCommandIDs(commandIDsByKey, result)
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
			"maxOmittedItems": agentenvelope.MaxOmittedItems,
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

func evidenceCommandKeys(result Result) []commandKey {
	byKey := map[string]struct{}{}
	add := func(key commandKey) {
		canonical := keyString(key)
		if _, planned := result.plannedCommandKeys[canonical]; planned {
			byKey[canonical] = struct{}{}
		}
	}
	for _, key := range result.MissingReceipts {
		add(key)
	}
	for _, items := range [][]receiptSummary{result.FailedReceipts, result.NotRunReceipts, result.BlockedReceipts} {
		for _, item := range items {
			add(item.commandKey)
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	resultKeys := make([]commandKey, 0, len(keys))
	for _, key := range keys {
		resultKeys = append(resultKeys, parseKey(key))
	}
	return resultKeys
}

func evidencePlannedCommandIDs(result Result) map[string]string {
	keys := make([]string, 0, len(result.plannedCommandKeys))
	for key := range result.plannedCommandKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ids := make(map[string]string, len(keys))
	// Canonical tuple ranks are injective within the plan, independently of
	// receipt status, display truncation, or a digest collision assumption.
	for index, key := range keys {
		ids[key] = evidenceLocalID(fmt.Sprintf("proofkit.agent.command.selective-evidence.%03d", index+1), result)
	}
	return ids
}

func evidenceReceiptRefs(result Result, commandIDs map[string]string, sourceContextRef string) ([]map[string]any, []map[string]any, map[string]string, int) {
	refs := []map[string]any{}
	contexts := []map[string]any{}
	contextIDs := map[string]string{}
	candidateCount := 0
	for index, receipt := range result.MissingReceipts {
		key := keyString(receipt)
		if _, planned := result.plannedCommandKeys[key]; !planned {
			continue
		}
		candidateCount++
		id, retained := commandIDs[key]
		if !retained || len(refs) == itemLimit {
			continue
		}
		refID := evidenceLocalID(fmt.Sprintf("proofkit.agent.receipt.required.selective-evidence.%03d", index+1), result)
		refs = append(refs, map[string]any{"commandId": id, "evidenceRefs": []any{sourceContextRef}, "kind": "required_receipt_class", "nonClaim": "Required receipt classes describe missing caller-owned evidence; they are not receipt artifacts.", "owner": "consumer_repository", "producer": nil, "producerAdmission": "required", "receiptRefId": refID, "ref": receipt.ID})
	}
	items := append(append([]receiptSummary{}, result.FailedReceipts...), result.NotRunReceipts...)
	items = append(items, result.BlockedReceipts...)
	for index, receipt := range items {
		key := keyString(receipt.commandKey)
		if _, planned := result.plannedCommandKeys[key]; !planned {
			continue
		}
		// Count the candidate before either the command cap or receipt cap drops it.
		candidateCount++
		id, retained := commandIDs[key]
		// ref is not a kernel local edge. Withhold the whole record if its
		// path context would be rejected later by structural operand admission.
		if !retained || len(refs) == itemLimit || unicodepolicy.ContainsUnsafeScalar(receipt.EvidenceRef) {
			continue
		}
		contextID, found := contextIDs[receipt.EvidenceRef]
		if !found {
			contextID = evidenceLocalID(fmt.Sprintf("proofkit.agent.context.selective-evidence.artifact.%03d", len(contexts)+1), result)
			contextIDs[receipt.EvidenceRef] = contextID
			contexts = append(contexts, map[string]any{"kind": "path", "nonClaim": "The caller-provided artifact path does not prove artifact existence, freshness, or producer admission.", "owner": "consumer_repository", "purpose": "Caller-provided receipt artifact locator.", "ref": receipt.EvidenceRef, "refId": contextID, "role": "evidence"})
		}
		refID := evidenceLocalID(fmt.Sprintf("proofkit.agent.receipt.artifact.selective-evidence.%03d", index+1), result)
		refs = append(refs, map[string]any{"commandId": id, "evidenceRefs": []any{sourceContextRef, contextID}, "kind": "receipt_artifact", "nonClaim": "Receipt artifact refs name local path contexts containing caller-provided metadata and do not prove freshness or producer admission.", "owner": "consumer_repository", "producer": nil, "producerAdmission": "unverified", "receiptRefId": refID, "ref": contextID})
	}
	return refs, contexts, contextIDs, candidateCount
}

func evidenceLocalID(base string, result Result) string {
	if base == result.Report.ReportID {
		return base + ".local"
	}
	return base
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
		result = append(result, map[string]any{"evidenceRefs": evidenceRefs, "escalation": "Inspect the full selective evidence report before treating receipt coverage as complete.", "nonClaim": "Omitted receipt counts do not summarize hidden receipt states semantically.", "omissionId": "proofkit.agent.omission.selective-evidence-receipts", "omittedCount": receiptOmitted, "reason": "selective evidence receipt refs lacked a retained command, safe artifact context, or receipt budget"})
	}
	return result
}

func retryCommandIDs(commandIDs map[string]string, result Result) []any {
	targets := map[string]struct{}{}
	for _, item := range result.MissingReceipts {
		targets[keyString(item)] = struct{}{}
	}
	for _, item := range result.FailedReceipts {
		targets[keyString(item.commandKey)] = struct{}{}
	}
	for _, item := range result.NotRunReceipts {
		targets[keyString(item.commandKey)] = struct{}{}
	}
	resultIDs := []any{}
	for key, id := range commandIDs {
		if _, wanted := targets[key]; wanted {
			resultIDs = append(resultIDs, id)
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
