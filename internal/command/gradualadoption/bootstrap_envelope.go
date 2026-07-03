package gradualadoption

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func BuildBootstrapEnvelope(raw any) (map[string]any, int, error) {
	result, err := buildBootstrap(raw)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return BootstrapEnvelope(result), result.ExitCode, nil
}

func BuildBootstrapEnvelopeFromContractEnvelope(raw any) (map[string]any, int, error) {
	input, err := BootstrapInputFromContractEnvelope(raw)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return BuildBootstrapEnvelope(input)
}

func BootstrapEnvelope(result BootstrapResult) map[string]any {
	commandRefs := []map[string]any{}
	commandIDByText := map[string]string{}
	for index, command := range result.NextCommands {
		commandID := fmt.Sprintf("proofkit.agent.command.bootstrap.%03d", index+1)
		commandIDByText[command] = commandID
		commandRefs = append(commandRefs, map[string]any{
			"command":   command,
			"commandId": commandID,
			"nonClaim":  "Proofkit reports this command but does not execute it or prove it passed.",
			"owner":     "consumer_repository",
			"purpose":   "Caller-owned observe-mode command emitted by bootstrap planning.",
		})
	}
	contextRefs := make([]map[string]any, 0, len(result.PlannedFiles))
	for index, rawFile := range result.PlannedFiles {
		file := rawFile.(map[string]any)
		purpose := file["purpose"].(string)
		if payloadKey, ok := file["payloadKey"].(string); ok && payloadKey != "" {
			purpose += "; payload key " + payloadKey
		}
		contextRefs = append(contextRefs, map[string]any{
			"kind":     "path",
			"nonClaim": "Bootstrap file refs route materialization only and do not prove file creation, freshness, or correctness.",
			"owner":    "consumer_repository",
			"purpose":  purpose,
			"ref":      file["path"],
			"refId":    fmt.Sprintf("proofkit.agent.context.bootstrap-file.%03d", index+1),
			"role":     bootstrapFileRole(file),
		})
	}
	actionPlan := []map[string]any{}
	for _, rawAction := range result.AgentActionPlan {
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
	contextIDs := envelopeMapValues(contextRefs, "refId")
	commandIDs := envelopeMapValues(commandRefs, "commandId")
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: result.Record.ReportID + ".agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Bootstrap report identity does not prove file creation, witness execution, freshness, or caller approval.",
			"reportId":    result.Record.ReportID,
			"reportKind":  result.Record.ReportKind,
			"stableHash":  nil,
			"state":       result.Record.State,
		},
		Bounds: map[string]any{
			"escalation":      "Caller must inspect the full bootstrap report when starter payload content is needed.",
			"fanout":          "bounded",
			"maxActionItems":  len(actionPlan),
			"maxCommandRefs":  len(commandRefs),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds cover envelope item counts only and do not prove tokenizer-specific budget or proof completeness.",
			"omittedCount":    0,
		},
		ContextRefs: contextRefs,
		RouteQuestions: []map[string]any{
			{"evidenceRefs": admit.StringSliceToAny(contextIDs), "nonClaim": "Bootstrap refs identify planned caller-owned files only; they do not prove the files exist.", "question": "what changed", "questionId": "proofkit.agent.question.what-changed"},
			{"evidenceRefs": admit.StringSliceToAny(commandIDs), "nonClaim": "Bootstrap commands are observe-mode planned commands, not pass evidence.", "question": "what proves it", "questionId": "proofkit.agent.question.what-proves-it"},
			{"evidenceRefs": admit.StringSliceToAny(contextIDs), "nonClaim": "The consuming repository owns materialization, review, and promotion.", "question": "who owns it", "questionId": "proofkit.agent.question.who-owns-it"},
		},
		ClarificationQuestion: []map[string]any{},
		ActionPlan:            actionPlan,
		Commands:              commandRefs,
		BlockedPreconditions:  []map[string]any{},
		Omitted:               []map[string]any{},
		ReceiptRefs:           []map[string]any{},
		NonClaims: []string{
			"Bootstrap agent envelopes do not approve enforcement, merge, rollout, or product readiness.",
			"Bootstrap agent envelopes do not execute native witnesses.",
			"Bootstrap agent envelopes do not include full starter payloads.",
			"Bootstrap agent envelopes do not write files.",
		},
	})
}

func bootstrapFileRole(file map[string]any) string {
	if file["payloadKey"] == "proofBinding" {
		return "proof_binding"
	}
	if file["payloadKey"] == "witnessPlanInput" {
		return "command_registry"
	}
	purpose := file["purpose"].(string)
	if strings.Contains(purpose, "module specification") {
		return "spec_source"
	}
	if strings.Contains(purpose, "profile") {
		return "owner_surface"
	}
	return "supporting"
}
