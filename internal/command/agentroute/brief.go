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
)

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
			"commandRef":                      "agent-route",
			"launcherProfile":                 launcherProfile,
			"outputArgs":                      briefDetailOutputArgs(),
			"requiresOriginalLauncherContext": true,
			"requiresOriginalInput":           true,
			"sourceReportDigest":              reportDigest,
			"sourceReportId":                  reportID,
		},
		"nextAction":      briefNextAction(nextCommands, reportID),
		"omissionSummary": briefOmissionSummary(report, availableCommandCount, omittedBlockerCount),
		"packetId":        reportID + ".agent-brief",
		"packetKind":      "proofkit.agent-route.brief",
		"routeFamily":     stringFromMap(report, "selectedRouteFamily"),
		"schemaVersion":   1,
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
	blockers := make([]any, 0, maxBriefBlockerItems)
	total := 0
	appendBounded := func(blocker map[string]any) {
		total++
		if len(blockers) < maxBriefBlockerItems {
			blockers = append(blockers, blocker)
		}
	}
	if stringFromMap(report, "state") == "blocked_unknown_goal" {
		appendBounded(map[string]any{
			"blockerId": reportID + ".blocker.unknown-goal",
			"kind":      "unknown_goal",
		})
	}
	requiredInputs, _ := report["requiredInputs"].([]any)
	for index, raw := range requiredInputs {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		appendBounded(map[string]any{
			"blockerId":           fmt.Sprintf("%s.blocker.required-input.%02d", reportID, index+1),
			"kind":                "missing_input",
			"sourceReportPointer": fmt.Sprintf("/requiredInputs/%d", index),
			"subject":             requiredInputLabel(item),
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
		appendBounded(map[string]any{
			"blockerId":           fmt.Sprintf("%s.blocker.observed-report.%02d", reportID, index+1),
			"kind":                "observed_report",
			"sourceReportPointer": fmt.Sprintf("/observedReports/%d", index),
			"state":               state,
			"subject":             stringFromMap(item, "kind"),
		})
	}
	return blockers, total - len(blockers)
}

func briefOmissionSummary(report map[string]any, availableCommandCount int, omittedBlockerCount int) map[string]any {
	alternativeCount := availableCommandCount
	if stringFromMap(report, "state") == "routed" && alternativeCount > 0 {
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
	action["argvState"] = "detail_required"
}
