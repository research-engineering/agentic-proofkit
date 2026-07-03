package selectivegateplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	contextLimit = 24
	commandLimit = 24
)

func AgentEnvelope(plan map[string]any) map[string]any {
	sourceHash := stableHash(plan)
	changedPaths := stringArrayFromAny(plan["changedPaths"])
	generatedArtifacts := mapArrayFromAny(plan["generatedArtifacts"])
	witnesses := mapArrayFromAny(plan["touchedRequirementWitnesses"])
	unknownEdges := mapArrayFromAny(plan["unknownEdges"])
	requiredCommands := mapArrayFromAny(plan["requiredCommands"])
	contextRefs := []map[string]any{
		{
			"kind":     "evidence",
			"nonClaim": "The hash identifies this plan payload only and does not prove command execution or freshness.",
			"owner":    "consumer_repository",
			"purpose":  "Stable hash of the caller-provided selective gate plan.",
			"ref":      sourceHash,
			"refId":    "proofkit.agent.context.selective-plan.001",
			"role":     "generated_lookup",
		},
	}
	for index, path := range changedPaths {
		contextRefs = append(contextRefs, contextRef(fmt.Sprintf("proofkit.agent.context.changed-path.%03d", index+1), "path", "owner_surface", path, "Caller-reported changed path used for selective proof planning.", "Changed path refs are caller-provided and do not prove git diff completeness."))
	}
	for index, artifact := range generatedArtifacts {
		pathValue, _ := artifact["path"].(string)
		contextRefs = append(contextRefs, contextRef(fmt.Sprintf("proofkit.agent.context.generated-artifact.%03d", index+1), "path", "generated_lookup", pathValue, "Generated artifact obligation selected by the caller-owned plan.", "Generated artifact refs do not prove freshness until caller-owned generators run."))
	}
	for index, witness := range witnesses {
		pathValue, _ := witness["path"].(string)
		contextRefs = append(contextRefs, contextRef(fmt.Sprintf("proofkit.agent.context.touched-witness.%03d", index+1), "path", "proof_binding", pathValue, "Requirement witness route touched by the caller-owned plan.", "Witness refs route proof work only and do not prove witness execution."))
	}
	for index, edge := range unknownEdges {
		pathValue, _ := edge["path"].(string)
		edgeID, _ := edge["edgeId"].(string)
		edgeClass, _ := edge["edgeClass"].(string)
		coverageState, _ := edge["coverageState"].(string)
		contextRefs = append(contextRefs, contextRef(fmt.Sprintf("proofkit.agent.context.unknown-edge.%03d", index+1), "path", "proof_binding", pathValue, fmt.Sprintf("Selective planner unknown edge %s (%s) is %s.", edgeID, edgeClass, coverageState), "Unknown-edge refs describe caller-provided planner uncertainty and do not prove fallback execution or scope completeness."))
	}
	allContextRefs := contextRefs
	if len(contextRefs) > contextLimit {
		contextRefs = contextRefs[:contextLimit]
	}
	commands := make([]map[string]any, 0, len(requiredCommands))
	for _, item := range requiredCommands {
		id, _ := item["id"].(string)
		commandText, _ := item["command"].(string)
		reason, _ := item["reason"].(string)
		commands = append(commands, map[string]any{
			"command":   commandText,
			"commandId": id,
			"nonClaim":  "Proofkit lists this command but does not execute it or prove it passed.",
			"owner":     "consumer_repository",
			"purpose":   fmt.Sprintf("Caller-owned selective proof command: %s", reason),
		})
	}
	allCommands := commands
	if len(commands) > commandLimit {
		commands = commands[:commandLimit]
	}
	commandIDs := make([]any, 0, len(commands))
	for _, item := range commands {
		commandIDs = append(commandIDs, item["commandId"])
	}
	commandIDs = sortedAnyStrings(commandIDs)
	receiptRefs := make([]map[string]any, 0, len(commands))
	for _, item := range commands {
		id, _ := item["commandId"].(string)
		receiptRefs = append(receiptRefs, map[string]any{
			"commandId":         id,
			"evidenceRefs":      []any{id},
			"kind":              "required_receipt_class",
			"nonClaim":          "Required receipt classes describe needed caller-owned evidence; they are not receipt artifacts.",
			"owner":             "consumer_repository",
			"producer":          nil,
			"producerAdmission": "required",
			"receiptRefId":      "proofkit.agent.receipt.required." + id,
			"ref":               id,
		})
	}
	failures := stringArrayFromAny(plan["failures"])
	omitted := planOmissions(len(allContextRefs)-len(contextRefs), len(allCommands)-len(commands))
	state := "passed"
	if plan["planState"] == "fail_closed" {
		state = "failed"
	}
	verifyInstruction := "No required commands are listed; inspect plan failures and caller policy before treating the scope as proven."
	verifyEvidenceRefs := refIDs(contextRefs)
	if len(commandIDs) > 0 {
		verifyInstruction = "Run the listed caller-owned proof commands or collect equivalent admitted receipts."
		verifyEvidenceRefs = commandIDs
	}
	blocked := make([]map[string]any, 0, len(failures))
	for index, failure := range failures {
		blocked = append(blocked, map[string]any{
			"description":    failure,
			"evidenceRefs":   []any{"proofkit.agent.context.selective-plan.001"},
			"nonClaim":       "Plan failures are caller-owned blockers and are not repaired by proofkit.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("proofkit.agent.blocked-precondition.selective-plan.%03d", index+1),
		})
	}
	clarifications := make([]map[string]any, 0, len(failures))
	for index, failure := range failures {
		clarifications = append(clarifications, map[string]any{
			"askWhen":            "The selective gate plan failed closed before command execution.",
			"blocking":           true,
			"evidenceRefs":       []any{"proofkit.agent.context.selective-plan.001"},
			"expectedAnswerKind": "owner_decision",
			"nonClaim":           "The question does not resolve the plan failure.",
			"owner":              "consumer_repository",
			"question":           fmt.Sprintf("Which caller-owned route or policy resolves this selective plan failure: %s?", failure),
			"questionId":         fmt.Sprintf("proofkit.agent.clarify.selective-plan-failure.%03d", index+1),
		})
	}
	fanout := "bounded"
	escalation := "Caller-owned receipts for listed commands are sufficient for this bounded envelope."
	if len(omitted) > 0 {
		fanout = "wide"
		escalation = "Caller must inspect the omitted selective plan items or run a wider/full caller-owned gate."
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: "proofkit.selective-gate-plan.agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Selective gate plan identity does not prove command execution, receipt freshness, or caller approval.",
			"reportId":    "proofkit.selective-gate-plan",
			"reportKind":  "proofkit.selective-gate-plan",
			"stableHash":  sourceHash,
			"state":       state,
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
			question("proofkit.agent.question.what-changed", "what changed", refIDs(contextRefs), "Changed-scope routing remains caller-owned."),
			question("proofkit.agent.question.what-proves-it", "what proves it", evidenceOr(commandIDs, refIDs(contextRefs)), "Command refs are planned witnesses, not pass evidence."),
			question("proofkit.agent.question.who-owns-it", "who owns it", refIDs(contextRefs), "The consuming repository owns all command execution, receipts, and policy decisions."),
		},
		ClarificationQuestion: clarifications,
		ActionPlan: []map[string]any{
			{
				"commandIds":   []any{},
				"evidenceRefs": sortedAnyStrings(refIDs(contextRefs)),
				"instruction":  "Load the listed changed paths, generated-artifact obligations, and touched witness routes before changing proof code.",
				"nonClaims":    sortedAnyStrings([]any{"Route guidance does not prove changed-path completeness.", "Route guidance does not approve repository edits."}),
				"owner":        "consumer_repository",
				"phase":        "route",
				"rationale":    "Selective planning is only sound when the agent understands the caller-provided changed scope and proof routes.",
				"stepId":       "proofkit.agent.selective-gate-plan.route",
			},
			{
				"commandIds":   commandIDs,
				"evidenceRefs": verifyEvidenceRefs,
				"instruction":  verifyInstruction,
				"nonClaims":    []any{"Verify guidance does not execute commands.", "Verify guidance does not prove receipt freshness or merge approval."},
				"owner":        "consumer_repository",
				"phase":        "verify",
				"rationale":    "Proofkit can plan command refs, but native execution and receipt production remain outside proofkit.",
				"stepId":       "proofkit.agent.selective-gate-plan.verify",
			},
		},
		Commands:             commands,
		BlockedPreconditions: blocked,
		Omitted:              omitted,
		ReceiptRefs:          receiptRefs,
		NonClaims: []string{
			"Selective gate plan envelopes do not approve merge, rollout, or repository policy.",
			"Selective gate plan envelopes do not execute native witnesses.",
			"Selective gate plan envelopes do not prove command pass evidence.",
			"Selective gate plan envelopes do not prove receipt freshness.",
		},
	})
}

func stableHash(value any) string {
	output, err := stablejson.Marshal(value)
	if err != nil {
		return "sha256:"
	}
	hash := sha256.Sum256(output)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func stringArrayFromAny(value any) []string {
	values, ok := value.([]any)
	if !ok {
		return []string{}
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func mapArrayFromAny(value any) []map[string]any {
	values, ok := value.([]any)
	if !ok {
		return []map[string]any{}
	}
	result := make([]map[string]any, 0, len(values))
	for _, item := range values {
		if record, ok := item.(map[string]any); ok {
			result = append(result, record)
		}
	}
	return result
}

func contextRef(id string, kind string, role string, ref string, purpose string, nonClaim string) map[string]any {
	return map[string]any{"kind": kind, "nonClaim": nonClaim, "owner": "consumer_repository", "purpose": purpose, "ref": ref, "refId": id, "role": role}
}

func question(id string, text string, evidenceRefs []any, nonClaim string) map[string]any {
	return map[string]any{"evidenceRefs": sortedAnyStrings(evidenceRefs), "nonClaim": nonClaim, "question": text, "questionId": id}
}

func refIDs(refs []map[string]any) []any {
	result := make([]any, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ref["refId"])
	}
	return result
}

func evidenceOr(primary []any, fallback []any) []any {
	if len(primary) > 0 {
		return sortedAnyStrings(primary)
	}
	return sortedAnyStrings(fallback)
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

func planOmissions(contextOmitted int, commandOmitted int) []map[string]any {
	omitted := []map[string]any{}
	if contextOmitted > 0 {
		omitted = append(omitted, map[string]any{
			"evidenceRefs": []any{"proofkit.agent.context.selective-plan.001"},
			"escalation":   "Inspect the full selective gate plan before treating this envelope as complete.",
			"nonClaim":     "Omitted context counts do not summarize the hidden items semantically.",
			"omissionId":   "proofkit.agent.omission.selective-plan-context",
			"omittedCount": contextOmitted,
			"reason":       "selective plan context exceeded bounded envelope context limit",
		})
	}
	if commandOmitted > 0 {
		omitted = append(omitted, map[string]any{
			"evidenceRefs": []any{"proofkit.agent.context.selective-plan.001"},
			"escalation":   "Run a wider/full caller-owned gate or inspect the full selective gate plan.",
			"nonClaim":     "Omitted command counts are not pass evidence for omitted commands.",
			"omissionId":   "proofkit.agent.omission.selective-plan-commands",
			"omittedCount": commandOmitted,
			"reason":       "selective plan commands exceeded bounded envelope command limit",
		})
	}
	return omitted
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
