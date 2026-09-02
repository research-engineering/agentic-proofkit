package agentroute

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type EnvelopeMode string

const (
	EnvelopeModeBrief EnvelopeMode = "brief"
	EnvelopeModeFull  EnvelopeMode = "full"

	maxAgentBriefBytes   = 3072
	maxBriefBlockerItems = 4
)

func AgentBrief(report map[string]any) (map[string]any, error) {
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
	packet := map[string]any{
		"blockers":           blockers,
		"boundaryPolicyRefs": []any{"NC-PROOFKIT-SPEC-005", "NC-PROOFKIT-SPEC-026"},
		"contextRefs":        briefContextRefs(nextCommands, reportID),
		"detailAccess": map[string]any{
			"availableModes":        []any{"full", "report"},
			"commandRef":            "agent-route",
			"requiresOriginalInput": true,
			"sourceReportDigest":    reportDigest,
			"sourceReportId":        reportID,
		},
		"nextAction":      briefNextAction(nextCommands, reportID),
		"omissionSummary": briefOmissionSummary(report, nextCommands, omittedBlockerCount),
		"packetId":        reportID + ".agent-brief",
		"packetKind":      "proofkit.agent-route.brief",
		"routeFamily":     stringFromMap(report, "selectedRouteFamily"),
		"schemaVersion":   1,
		"state":           stringFromMap(report, "state"),
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

func briefNextAction(commands []map[string]any, reportID string) any {
	if len(commands) == 0 {
		return nil
	}
	command := commands[0]
	return map[string]any{
		"actionId":   reportID + ".action." + commandRefSuffix(command),
		"argv":       command["argv"],
		"argvState":  "inline",
		"commandId":  commandID(reportID, command),
		"commandRef": stringFromMap(command, "command"),
		"owner":      "consumer_repository",
	}
}

func briefContextRefs(commands []map[string]any, reportID string) []any {
	if len(commands) == 0 {
		return []any{}
	}
	argv := stringsFromAny(commands[0]["argv"])
	refs := []any{}
	for index := 0; index < len(argv)-1; index++ {
		role := ""
		switch argv[index] {
		case "--input":
			role = "caller_owned_input"
		case "--repo-root":
			role = "caller_owned_repo_root"
		default:
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
	blockers := []any{}
	for index, item := range mapsFromAny(report["requiredInputs"]) {
		blockers = append(blockers, map[string]any{
			"blockerId":           fmt.Sprintf("%s.blocker.required-input.%02d", reportID, index+1),
			"kind":                "missing_input",
			"sourceReportPointer": fmt.Sprintf("/requiredInputs/%d", index),
			"subject":             requiredInputLabel(item),
		})
	}
	for index, item := range mapsFromAny(report["observedReports"]) {
		state := stringFromMap(item, "state")
		if state == "passed" {
			continue
		}
		blockers = append(blockers, map[string]any{
			"blockerId":           fmt.Sprintf("%s.blocker.observed-report.%02d", reportID, index+1),
			"kind":                "observed_report",
			"sourceReportPointer": fmt.Sprintf("/observedReports/%d", index),
			"state":               state,
			"subject":             stringFromMap(item, "kind"),
		})
	}
	if len(blockers) == 0 && stringFromMap(report, "state") == "blocked_unknown_goal" {
		blockers = append(blockers, map[string]any{
			"blockerId": reportID + ".blocker.unknown-goal",
			"kind":      "unknown_goal",
		})
	}
	if len(blockers) <= maxBriefBlockerItems {
		return blockers, 0
	}
	return blockers[:maxBriefBlockerItems], len(blockers) - maxBriefBlockerItems
}

func briefOmissionSummary(report map[string]any, commands []map[string]any, omittedBlockerCount int) map[string]any {
	alternativeCount := len(commands)
	if alternativeCount > 0 {
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
		"sourceOmittedCommandCount": len(mapsFromAny(report["omitted"])),
	}
}

func compactBriefAction(packet map[string]any) {
	action, ok := packet["nextAction"].(map[string]any)
	if !ok {
		return
	}
	delete(action, "argv")
	action["argvState"] = "detail_required"
}
