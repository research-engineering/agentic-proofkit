package proofobligationalgebra

import (
	"fmt"
	"sort"
)

// analyzeGraph keeps reachability total even when the admitted graph contains
// missing references or cycles. Depth is defined only for the acyclic region.
func analyzeGraph(obligations []obligationInput, byID map[string]obligationInput) (graphAnalysis, error) {
	analysis := graphAnalysis{
		blockedByCycle: make(map[string]bool, len(obligations)),
		cycleAffected:  make(map[string]bool, len(obligations)),
		depthByID:      make(map[string]int, len(obligations)),
		transitiveByID: make(map[string][]string, len(obligations)),
	}
	totalReferences := 0
	for _, item := range obligations {
		reachable := reachableChildIDs(item.ObligationID, byID)
		analysis.transitiveByID[item.ObligationID] = reachable
		analysis.blockedByCycle[item.ObligationID] = containsID(reachable, item.ObligationID)
		totalReferences += len(reachable)
		if totalReferences > maxTransitiveReferenceCount {
			return graphAnalysis{}, fmt.Errorf("proof obligation algebra transitive output exceeds the %d-reference limit", maxTransitiveReferenceCount)
		}
	}

	parentsByChild := make(map[string][]string, len(obligations))
	remainingChildren := make(map[string]int, len(obligations))
	for _, item := range obligations {
		for _, childID := range item.ChildObligationIDs {
			if _, declared := byID[childID]; !declared {
				if analysis.depthByID[item.ObligationID] < 1 {
					analysis.depthByID[item.ObligationID] = 1
				}
				continue
			}
			remainingChildren[item.ObligationID]++
			parentsByChild[childID] = append(parentsByChild[childID], item.ObligationID)
		}
	}
	queue := make([]string, 0, len(obligations))
	for _, item := range obligations {
		if remainingChildren[item.ObligationID] == 0 {
			queue = append(queue, item.ObligationID)
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, parentID := range parentsByChild[current] {
			if depth := analysis.depthByID[current] + 1; depth > analysis.depthByID[parentID] {
				analysis.depthByID[parentID] = depth
			}
			remainingChildren[parentID]--
			if remainingChildren[parentID] == 0 {
				queue = append(queue, parentID)
			}
		}
	}
	for id, remaining := range remainingChildren {
		if remaining > 0 {
			analysis.cycleAffected[id] = true
		}
	}
	return analysis, nil
}

func reachableChildIDs(rootID string, byID map[string]obligationInput) []string {
	root, ok := byID[rootID]
	if !ok {
		return nil
	}
	queue := append([]string(nil), root.ChildObligationIDs...)
	seen := make(map[string]struct{}, len(queue))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		if item, declared := byID[current]; declared {
			queue = append(queue, item.ChildObligationIDs...)
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func containsID(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}
