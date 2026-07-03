package agentroute

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func BuildEnvelope(raw any) (map[string]any, int, error) {
	report, exitCode, err := Build(raw)
	if err != nil {
		return nil, 1, err
	}
	return AgentEnvelope(report), exitCode, nil
}

func AgentEnvelope(report map[string]any) map[string]any {
	routeState := stringFromMap(report, "state")
	sourceState := "failed"
	if routeState == "routed" {
		sourceState = "passed"
	}
	reportID := stringFromMap(report, "reportId")
	if reportID == "" {
		reportID = "proofkit.agent-route.unknown"
	}
	nextCommands := mapsFromAny(report["nextCommands"])
	requiredInputs := mapsFromAny(report["requiredInputs"])
	observedReports := mapsFromAny(report["observedReports"])
	omitted := mapsFromAny(report["omitted"])
	guidanceSlice := mapFromAny(report["guidanceSlice"])
	contextRefs := guidanceContextRefs(guidanceSlice, reportID)
	contextRefs = append(contextRefs, inputContextRefs(nextCommands, reportID)...)
	commandRefs := commandContextRefs(nextCommands, reportID)
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: reportID + ".agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Agent route source state proves route selection only, not downstream command execution or proof freshness.",
			"reportId":    reportID,
			"reportKind":  "proofkit.agent-route",
			"routeState":  routeState,
			"stableHash":  nil,
			"state":       sourceState,
		},
		Bounds: map[string]any{
			"escalation":      "Escalate to the consuming repository owner when the selected route lacks required input, native witness evidence, or policy authority.",
			"fanout":          "bounded",
			"maxActionItems":  len(nextCommands) + len(requiredInputs),
			"maxCommandRefs":  len(commandRefs),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Agent-route bounds count route refs only and do not prove tokenizer-specific budget coverage.",
			"omittedCount":    len(omitted),
		},
		ContextRefs:           contextRefs,
		RouteQuestions:        routeQuestions(reportID),
		ClarificationQuestion: clarificationQuestions(requiredInputs, reportID),
		ActionPlan:            actionPlan(nextCommands, requiredInputs, reportID),
		Commands:              commandRefs,
		BlockedPreconditions:  blockedPreconditions(requiredInputs, observedReports, reportID),
		Omitted:               omittedItems(omitted, reportID),
		ReceiptRefs:           []map[string]any{},
		NonClaims:             envelopeNonClaims(report, guidanceSlice),
	})
}

func guidanceContextRefs(slice map[string]any, reportID string) []map[string]any {
	contextRefs := []map[string]any{
		{
			"description": "Selected compact guidance slice for the agent route.",
			"path":        "proofkit.agent-route.guidanceSlice",
			"refId":       reportID + ".guidance-slice",
			"role":        "guidance_slice",
			"selector":    stringFromMap(slice, "sliceId"),
		},
	}
	for _, item := range mapsFromAny(slice["authorityRefs"]) {
		contextRefs = append(contextRefs, map[string]any{
			"description": stringFromMap(item, "reason"),
			"path":        stringFromMap(item, "path"),
			"refId":       stringFromMap(item, "refId"),
			"role":        stringFromMap(item, "role"),
			"selector":    stringFromMap(item, "selector"),
		})
	}
	return contextRefs
}

func inputContextRefs(commands []map[string]any, reportID string) []map[string]any {
	refs := []map[string]any{}
	seen := map[string]struct{}{}
	for _, command := range commands {
		inputRef := commandInputRef(command)
		if inputRef == "" {
			continue
		}
		if _, ok := seen[inputRef]; ok {
			continue
		}
		seen[inputRef] = struct{}{}
		refs = append(refs, map[string]any{
			"description": "Caller-owned input selected by agent-route.",
			"path":        inputRef,
			"refId":       inputRefID(reportID, inputRef),
			"role":        "caller_owned_input",
			"selector":    inputRef,
		})
	}
	return refs
}

func commandContextRefs(commands []map[string]any, reportID string) []map[string]any {
	refs := []map[string]any{}
	for _, command := range commands {
		commandName := stringFromMap(command, "command")
		if commandName == "" {
			continue
		}
		refs = append(refs, map[string]any{
			"argv":          command["argv"],
			"commandId":     commandID(reportID, command),
			"display":       commandName,
			"nonClaim":      "Agent-route command refs do not execute commands or admit command results.",
			"owner":         "consumer_repository",
			"proofkitRoute": commandName,
		})
	}
	return refs
}

func routeQuestions(reportID string) []map[string]any {
	return []map[string]any{
		{
			"evidenceRefs": []any{reportID},
			"nonClaim":     "This question routes inspection only; it does not approve edits.",
			"question":     "What caller-owned input or boundary is the agent expected to inspect next?",
			"questionId":   reportID + ".question.what-to-inspect",
		},
		{
			"evidenceRefs": []any{reportID},
			"nonClaim":     "This question does not execute or validate native witnesses.",
			"question":     "Which Proofkit command produces the next deterministic report?",
			"questionId":   reportID + ".question.next-command",
		},
		{
			"evidenceRefs": []any{reportID},
			"nonClaim":     "This question keeps policy authority with the caller.",
			"question":     "Which decision remains owned by the consuming repository after Proofkit reports?",
			"questionId":   reportID + ".question.owner-decision",
		},
	}
}

func clarificationQuestions(requiredInputs []map[string]any, reportID string) []map[string]any {
	questions := []map[string]any{}
	for index, item := range requiredInputs {
		questions = append(questions, map[string]any{
			"askWhen":            "The selected route is blocked because a required caller-owned input is missing.",
			"blocking":           true,
			"evidenceRefs":       []any{reportID},
			"expectedAnswerKind": "caller_owned_input_ref",
			"nonClaim":           "Supplying the input ref does not approve its content.",
			"owner":              "consumer_repository",
			"question":           "Which caller-owned input file or report should satisfy " + requiredInputLabel(item) + "?",
			"questionId":         fmt.Sprintf("%s.clarify.required-input.%02d", reportID, index+1),
		})
	}
	return questions
}

func actionPlan(commands []map[string]any, requiredInputs []map[string]any, reportID string) []map[string]any {
	actions := []map[string]any{}
	for _, item := range requiredInputs {
		actions = append(actions, map[string]any{
			"commandIds":   []any{},
			"evidenceRefs": []any{reportID},
			"instruction":  "Provide " + requiredInputLabel(item) + " before running the selected Proofkit route.",
			"nonClaims":    []any{"Missing-input actions do not approve caller-owned input content."},
			"owner":        "consumer_repository",
			"phase":        "route",
			"rationale":    stringFromMap(item, "reason"),
			"stepId":       reportID + ".action.provide-" + sanitizeRefID(requiredInputLabel(item)),
		})
	}
	for _, command := range commands {
		actions = append(actions, map[string]any{
			"commandIds":   []any{commandID(reportID, command)},
			"evidenceRefs": []any{reportID},
			"instruction":  "Run the selected Proofkit command only after the consuming repository admits the caller-owned input ref.",
			"nonClaims":    []any{"Route actions do not execute commands, prove command success, or approve merge."},
			"owner":        "consumer_repository",
			"phase":        "route",
			"rationale":    stringFromMap(command, "why"),
			"stepId":       reportID + ".action." + commandRefSuffix(command),
		})
	}
	return actions
}

func blockedPreconditions(requiredInputs []map[string]any, observedReports []map[string]any, reportID string) []map[string]any {
	blocked := []map[string]any{}
	for index, item := range requiredInputs {
		blocked = append(blocked, map[string]any{
			"description":    "Missing " + requiredInputLabel(item) + ".",
			"evidenceRefs":   []any{reportID},
			"nonClaim":       "A missing input precondition does not decide requirement meaning, proof adequacy, or merge.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("%s.blocked.required-input.%02d", reportID, index+1),
		})
	}
	for index, item := range observedReports {
		if stringFromMap(item, "state") == "passed" {
			continue
		}
		blocked = append(blocked, map[string]any{
			"description":    "Observed " + stringFromMap(item, "kind") + " report is " + stringFromMap(item, "state") + ".",
			"evidenceRefs":   []any{stringFromMap(item, "ref")},
			"nonClaim":       "Observed report state blocks route guidance but does not let Proofkit repair caller-owned evidence.",
			"owner":          "consumer_repository",
			"preconditionId": fmt.Sprintf("%s.blocked.observed-report.%02d", reportID, index+1),
		})
	}
	return blocked
}

func omittedItems(omitted []map[string]any, reportID string) []map[string]any {
	items := []map[string]any{}
	for index, item := range omitted {
		items = append(items, map[string]any{
			"escalation":   "Provide the omitted command's caller-owned input or choose a narrower route.",
			"omissionId":   fmt.Sprintf("%s.omitted.command.%02d", reportID, index+1),
			"omittedCount": 1,
			"reason":       stringFromMap(item, "reason"),
			"subject":      stringFromMap(item, "command"),
		})
	}
	return items
}

func envelopeNonClaims(report map[string]any, guidanceSlice map[string]any) []string {
	values := []string{}
	values = append(values, stringsFromAny(report["nonClaims"])...)
	values = append(values, stringsFromAny(guidanceSlice["nonClaims"])...)
	values = append(values,
		"agent-route envelopes are bounded route packets, not proof execution or policy approval.",
		"agent-route envelopes cite compact guidance slices instead of embedding full owner documents.",
	)
	return sortedUniqueStrings(values)
}

func commandInputRef(command map[string]any) string {
	argv := stringsFromAny(command["argv"])
	for index := 0; index < len(argv)-1; index++ {
		if argv[index] == "--input" {
			return argv[index+1]
		}
	}
	return ""
}

func commandID(reportID string, command map[string]any) string {
	return reportID + ".command." + commandRefSuffix(command)
}

func commandRefSuffix(command map[string]any) string {
	commandName := sanitizeRefID(stringFromMap(command, "command"))
	if commandName == "" {
		commandName = "command"
	}
	argv := stringsFromAny(command["argv"])
	if len(argv) == 0 {
		return commandName + "." + shortTextHash(commandName)
	}
	return commandName + "." + shortTextHash(strings.Join(argv, "\x00"))
}

func inputRefID(reportID string, inputRef string) string {
	return reportID + ".input." + shortTextHash(inputRef)
}

func shortTextHash(text string) string {
	return strings.TrimPrefix(digest.SHA256TextRef(text), "sha256:")[:16]
}

func requiredInputLabel(item map[string]any) string {
	if kind := stringFromMap(item, "kind"); kind != "" {
		return kind
	}
	if values, ok := item["oneOf"].([]any); ok {
		parts := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				parts = append(parts, text)
			}
		}
		sort.Strings(parts)
		return strings.Join(parts, "_or_")
	}
	return "caller_owned_input"
}

func mapFromAny(raw any) map[string]any {
	if value, ok := raw.(map[string]any); ok {
		return value
	}
	return map[string]any{}
}

func mapsFromAny(raw any) []map[string]any {
	items, ok := raw.([]any)
	if !ok {
		return []map[string]any{}
	}
	values := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if record, ok := item.(map[string]any); ok {
			values = append(values, record)
		}
	}
	return values
}

func stringFromMap(record map[string]any, key string) string {
	if value, ok := record[key].(string); ok {
		return value
	}
	return ""
}

func stringsFromAny(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			values = append(values, text)
		}
	}
	return values
}

func sanitizeRefID(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	lastSeparator := false
	for _, char := range value {
		isToken := (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
		if isToken {
			builder.WriteRune(char)
			lastSeparator = false
			continue
		}
		if !lastSeparator {
			builder.WriteByte('-')
			lastSeparator = true
		}
	}
	return strings.Trim(builder.String(), "-")
}
