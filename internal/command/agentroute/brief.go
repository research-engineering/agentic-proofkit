package agentroute

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type EnvelopeMode string

const (
	EnvelopeModeBrief EnvelopeMode = "brief"
	EnvelopeModeFull  EnvelopeMode = "full"

	briefBoundaryPolicyDerivedView = "REQ-PROOFKIT-SPEC-005"
	briefBoundaryPolicyRoutePacket = "REQ-PROOFKIT-SPEC-026"
	maxAgentBriefBytes             = 3072
	maxBriefBlockerItems           = 4
	briefPacketKind                = "proofkit.agent-route.brief"
	briefCommandRef                = "agent-route"
	briefSchemaVersion             = 1
	argvStateInline                = "inline"
	argvStateDetailRequired        = "detail_required"

	// Brief identities append these fixed grammars to the admitted route ID.
	briefPacketIDSuffix             = ".agent-brief"
	briefUnknownGoalBlockerSuffix   = ".blocker.unknown-goal"
	briefRequiredInputBlockerInfix  = ".blocker.required-input."
	briefObservedReportBlockerInfix = ".blocker.observed-report."
	briefBlockerUnknownGoal         = "unknown_goal"
	briefBlockerMissingInput        = "missing_input"
	briefBlockerObservedReport      = "observed_report"
)

// briefOperandRoles names the caller-owned artifact operands a brief may cite.
var briefOperandRoles = map[string]string{
	"--input":     callerOwnedInputRole,
	"--repo-root": "caller_owned_repo_root",
}

func AgentBrief(report map[string]any) (map[string]any, error) {
	packet, err := projectAgentBrief(report)
	if err != nil {
		return nil, err
	}
	encoded, err := stablejson.Marshal(packet)
	if err != nil {
		return nil, fmt.Errorf("serialize agent-route brief: %w", err)
	}
	if len(encoded) > maxAgentBriefBytes {
		compactBriefAction(packet)
		encoded, err = stablejson.Marshal(packet)
		if err != nil {
			return nil, fmt.Errorf("serialize compacted agent-route brief: %w", err)
		}
	}
	if len(encoded) > maxAgentBriefBytes {
		return nil, fmt.Errorf("agent-route brief exceeds %d bytes", maxAgentBriefBytes)
	}
	return packet, nil
}

func projectAgentBrief(report map[string]any) (map[string]any, error) {
	reportID := stringFromMap(report, "reportId")
	if reportID == "" {
		reportID = "proofkit.agent-route.unknown"
	}
	reportDigest, err := digest.StableJSONSHA256Ref(report)
	if err != nil {
		return nil, fmt.Errorf("digest agent-route report: %w", err)
	}

	nextCommands := mapsFromAny(report["nextCommands"])
	blockers, omittedBlockerCount := briefBlockers(report, reportID)
	summary := mapFromAny(report["summary"])
	availableCommandCount, ok := nonNegativeInt(summary["availableCommandCount"])
	if !ok {
		return nil, fmt.Errorf("agent-route report summary availableCommandCount must be a non-negative integer")
	}
	launcherProfile := stringFromMap(summary, "launcherProfile")
	if launcherProfile == "" {
		return nil, fmt.Errorf("agent-route report summary launcherProfile must be non-empty")
	}
	return map[string]any{
		"blockers":           blockers,
		"boundaryPolicyRefs": briefBoundaryPolicyRefs(),
		"contextRefs":        briefContextRefs(nextCommands, reportID),
		"detailAccess": map[string]any{
			"commandRef":                      briefCommandRef,
			"launcherProfile":                 launcherProfile,
			"outputArgs":                      briefDetailOutputArgs(),
			"requiresOriginalLauncherContext": true,
			"requiresOriginalInput":           true,
			"sourceReportDigest":              reportDigest,
			"sourceReportId":                  reportID,
		},
		"nextAction":      briefNextAction(nextCommands, reportID),
		"omissionSummary": briefOmissionSummary(report, availableCommandCount, omittedBlockerCount),
		"packetId":        reportID + briefPacketIDSuffix,
		"packetKind":      briefPacketKind,
		"routeFamily":     stringFromMap(report, "selectedRouteFamily"),
		"schemaVersion":   briefSchemaVersion,
		"state":           stringFromMap(report, "state"),
	}, nil
}

func briefBoundaryPolicyRefs() []any {
	return []any{briefBoundaryPolicyDerivedView, briefBoundaryPolicyRoutePacket}
}

func briefDetailOutputArgs() map[string]any {
	return map[string]any{
		"full":   []any{"--agent-envelope", "--agent-envelope-mode", "full"},
		"report": []any{},
	}
}

func briefNextAction(commands []map[string]any, reportID string) any {
	if len(commands) == 0 {
		return nil
	}
	command := commands[0]
	return map[string]any{
		"actionId":   reportID + actionIDInfix + commandRefSuffix(command),
		"argv":       command["argv"],
		"argvState":  argvStateInline,
		"commandId":  commandID(reportID, command),
		"commandRef": stringFromMap(command, "command"),
		"owner":      consumerOwner,
	}
}

func briefContextRefs(commands []map[string]any, reportID string) []any {
	if len(commands) == 0 {
		return []any{}
	}
	argv := stringsFromAny(commands[0]["argv"])
	refs := []any{}
	for index := 0; index < len(argv)-1; index++ {
		role, operand := briefOperandRoles[argv[index]]
		if !operand {
			continue
		}
		ref := argv[index+1]
		refs = append(refs, map[string]any{
			"refId":               inputRefID(reportID, argv[index]+"\x00"+ref),
			"role":                role,
			"sourceReportPointer": fmt.Sprintf("/nextCommands/0/argv/%d", index+1),
		})
		index++
	}
	return refs
}

func briefBlockers(report map[string]any, reportID string) ([]any, int) {
	blockers := make([]any, 0, maxBriefBlockerItems)
	total := 0
	if stringFromMap(report, "state") == stateBlockedUnknownGoal {
		appendBoundedBriefBlocker(&blockers, &total, func() map[string]any {
			return map[string]any{
				"blockerId": reportID + briefUnknownGoalBlockerSuffix,
				"kind":      briefBlockerUnknownGoal,
			}
		})
	}
	requiredInputs, _ := report["requiredInputs"].([]any)
	for index, raw := range requiredInputs {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		appendBoundedBriefBlocker(&blockers, &total, func() map[string]any {
			return map[string]any{
				"blockerId":           fmt.Sprintf("%s%s%02d", reportID, briefRequiredInputBlockerInfix, index+1),
				"kind":                briefBlockerMissingInput,
				"sourceReportPointer": fmt.Sprintf("/requiredInputs/%d", index),
				"subject":             requiredInputLabel(item),
			}
		})
	}
	observedReports, _ := report["observedReports"].([]any)
	for index, raw := range observedReports {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		state := stringFromMap(item, "state")
		if state == "passed" {
			continue
		}
		appendBoundedBriefBlocker(&blockers, &total, func() map[string]any {
			return map[string]any{
				"blockerId":           fmt.Sprintf("%s%s%02d", reportID, briefObservedReportBlockerInfix, index+1),
				"kind":                briefBlockerObservedReport,
				"sourceReportPointer": fmt.Sprintf("/observedReports/%d", index),
				"state":               state,
				"subject":             stringFromMap(item, "kind"),
			}
		})
	}
	return blockers, total - len(blockers)
}

func appendBoundedBriefBlocker(blockers *[]any, total *int, build func() map[string]any) {
	*total = *total + 1
	if len(*blockers) >= maxBriefBlockerItems {
		return
	}
	*blockers = append(*blockers, build())
}

func briefOmissionSummary(report map[string]any, availableCommandCount int, omittedBlockerCount int) map[string]any {
	alternativeCount := availableCommandCount
	if stringFromMap(report, "state") == stateRouted && alternativeCount > 0 {
		alternativeCount--
	}
	return map[string]any{
		"availableAlternativeCommandCount": alternativeCount,
		"detailClasses": []any{
			"explanatory_prose",
			"full_action_plan",
			"policy_non_claim_text",
			"route_questions",
		},
		"omittedBlockerCount":       omittedBlockerCount,
		"sourceOmittedCommandCount": omittedCommandCount(report["omitted"]),
	}
}

func omittedCommandCount(raw any) int {
	count := 0
	for _, item := range mapsFromAny(raw) {
		if stringFromMap(item, "command") != "" {
			count++
		}
	}
	return count
}

func nonNegativeInt(raw any) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, value >= 0
	case json.Number:
		integer, err := value.Int64()
		if err != nil || integer < 0 || int64(int(integer)) != integer {
			return 0, false
		}
		return int(integer), true
	default:
		return 0, false
	}
}

func compactBriefAction(packet map[string]any) {
	action, ok := packet["nextAction"].(map[string]any)
	if !ok {
		return
	}
	delete(action, "argv")
	action["argvState"] = argvStateDetailRequired
}
