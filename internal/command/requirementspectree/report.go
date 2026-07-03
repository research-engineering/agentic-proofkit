package requirementspectree

import (
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func buildRecord(input admittedInput, validation validationResult) report.Record {
	state := "passed"
	if len(validation.Failures) > 0 {
		state = "failed"
	}
	nonClaims := append([]string{}, boundaryNonClaims...)
	sort.Strings(nonClaims)
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.TreeID,
		State:         state,
		Summary: map[string]any{
			"callerNonClaimCount": callerNonClaimCount(input),
			"edgeCount":           len(input.Edges),
			"failureCount":        len(validation.Failures),
			"maxDepth":            validation.MaxDepth,
			"nodeCount":           len(input.Nodes),
			"overlayCount":        len(input.Overlays),
			"sourceRefCount":      len(validation.SourceRefIDs),
			"staleSourceRefCount": len(validation.StaleSourceRefIDs),
			"visitedNodeCount":    validation.VisitedNodeCount,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "boundaryNonClaims", Value: admit.StringSliceToAny(nonClaims)},
			{Key: "callerNonClaims", Value: callerNonClaimsDiagnostic(input)},
			{Key: "edges", Value: edgesDiagnostic(input.Edges)},
			{Key: "failures", Value: admit.StringSliceToAny(validation.Failures)},
			{Key: "nodes", Value: nodesDiagnostic(input.Nodes)},
			{Key: "overlays", Value: overlaysDiagnostic(input.Overlays)},
		},
		RuleResults: ruleResults(validation.Failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
}

func nodesDiagnostic(nodes []node) []any {
	values := make([]any, 0, len(nodes))
	for _, item := range nodes {
		sourceRefIDs := make([]string, 0, len(item.SourceRefs))
		for _, ref := range item.SourceRefs {
			sourceRefIDs = append(sourceRefIDs, ref.SourceRefID)
		}
		sort.Strings(sourceRefIDs)
		values = append(values, map[string]any{
			"callerNonClaims": admit.StringSliceToAny(item.CallerNonClaims),
			"displayOrder":    item.DisplayOrder,
			"label":           item.Label,
			"nodeId":          item.NodeID,
			"nodeKind":        item.NodeKind,
			"sourceRefIds":    admit.StringSliceToAny(sourceRefIDs),
		})
	}
	sort.SliceStable(values, func(left int, right int) bool {
		leftMap := values[left].(map[string]any)
		rightMap := values[right].(map[string]any)
		leftOrder := leftMap["displayOrder"].(int)
		rightOrder := rightMap["displayOrder"].(int)
		if leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		return leftMap["nodeId"].(string) < rightMap["nodeId"].(string)
	})
	return values
}

func edgesDiagnostic(edges []edge) []any {
	values := make([]any, 0, len(edges))
	for _, item := range edges {
		values = append(values, map[string]any{
			"childNodeId":  item.ChildNodeID,
			"parentNodeId": item.ParentNodeID,
		})
	}
	return values
}

func overlaysDiagnostic(overlays []overlay) []any {
	values := make([]any, 0, len(overlays))
	for _, item := range overlays {
		value := map[string]any{
			"callerNonClaims": admit.StringSliceToAny(item.CallerNonClaims),
			"label":           item.Label,
			"overlayId":       item.OverlayID,
			"overlayKind":     item.OverlayKind,
			"refId":           item.RefID,
			"refKind":         item.RefKind,
			"targetNodeId":    item.TargetNodeID,
		}
		if item.RefPath != "" {
			value["digestAlgorithm"] = item.DigestAlgorithm
			value["refDigest"] = item.RefDigest
			value["refPath"] = item.RefPath
		}
		values = append(values, value)
	}
	return values
}

func callerNonClaimsDiagnostic(input admittedInput) map[string]any {
	nodeClaims := []any{}
	for _, item := range input.Nodes {
		if len(item.CallerNonClaims) == 0 {
			continue
		}
		nodeClaims = append(nodeClaims, map[string]any{
			"nodeId":    item.NodeID,
			"nonClaims": admit.StringSliceToAny(item.CallerNonClaims),
		})
	}
	overlayClaims := []any{}
	for _, item := range input.Overlays {
		if len(item.CallerNonClaims) == 0 {
			continue
		}
		overlayClaims = append(overlayClaims, map[string]any{
			"nonClaims": admit.StringSliceToAny(item.CallerNonClaims),
			"overlayId": item.OverlayID,
		})
	}
	return map[string]any{
		"nodes":    nodeClaims,
		"overlays": overlayClaims,
		"root":     admit.StringSliceToAny(input.CallerNonClaims),
	}
}

func callerNonClaimCount(input admittedInput) int {
	total := len(input.CallerNonClaims)
	for _, item := range input.Nodes {
		total += len(item.CallerNonClaims)
	}
	for _, item := range input.Overlays {
		total += len(item.CallerNonClaims)
	}
	return total
}

func ruleResults(failures []string) []report.RuleResult {
	return []report.RuleResult{
		ruleResult("proofkit.requirement-spec-tree.topology", failuresWithPrefix(failures, "topology."), "Spec tree topology admits exactly one reachable parent-owned tree rooted at rootNodeId."),
		ruleResult("proofkit.requirement-spec-tree.source_refs", failuresWithPrefix(failures, "source_ref."), "Spec tree source refs admit one source-reference authority and caller-provided digest facts."),
		ruleResult("proofkit.requirement-spec-tree.overlays", failuresWithPrefix(failures, "overlay."), "Spec tree overlays are opaque routing refs to admitted nodes and source refs."),
		{
			RuleID:      "proofkit.requirement-spec-tree.non_claims",
			Status:      "passed",
			Message:     "Caller non-claims were admitted as display-only text and kept separate from Proofkit boundary non-claims.",
			Diagnostics: []report.Diagnostic{},
		},
	}
}

func ruleResult(ruleID string, failures []string, passedMessage string) report.RuleResult {
	status := "passed"
	message := passedMessage
	if len(failures) > 0 {
		status = "failed"
		message = strings.TrimPrefix(ruleID, "proofkit.requirement-spec-tree.") + " validation failed"
	}
	return report.RuleResult{
		RuleID:  ruleID,
		Status:  status,
		Message: message,
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
		},
	}
}

func failuresWithPrefix(failures []string, prefix string) []string {
	result := []string{}
	for _, failure := range failures {
		if strings.HasPrefix(failure, prefix) {
			result = append(result, failure)
		}
	}
	return result
}
