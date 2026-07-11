package requirementspectree

import (
	"fmt"
	"sort"
)

type validationResult struct {
	Failures          []string
	MaxDepth          int
	SourceRefIDs      map[string]struct{}
	StaleSourceRefIDs []string
	VisitedNodeCount  int
}

func validate(input admittedInput) validationResult {
	validator := treeValidator{
		childrenByParent: map[string][]string{},
		failures:         []string{},
		nodeByID:         map[string]node{},
		parentByChild:    map[string][]string{},
		sourceRefIDs:     map[string]struct{}{},
	}
	validator.indexNodes(input)
	validator.indexEdges(input)
	validator.validateTopology(input)
	validator.validateOverlays(input)
	validator.sort()
	return validationResult{
		Failures:          validator.failures,
		MaxDepth:          validator.maxDepth,
		SourceRefIDs:      validator.sourceRefIDs,
		StaleSourceRefIDs: validator.staleSourceRefIDs,
		VisitedNodeCount:  len(validator.visited),
	}
}

type treeValidator struct {
	childrenByParent  map[string][]string
	failures          []string
	maxDepth          int
	nodeByID          map[string]node
	parentByChild     map[string][]string
	sourceRefIDs      map[string]struct{}
	staleSourceRefIDs []string
	visited           map[string]int
	visiting          map[string]struct{}
}

func (validator *treeValidator) indexNodes(input admittedInput) {
	for _, item := range input.Nodes {
		if _, exists := validator.nodeByID[item.NodeID]; exists {
			validator.fail("topology.duplicate_node", item.NodeID)
			continue
		}
		validator.nodeByID[item.NodeID] = item
		for _, ref := range item.SourceRefs {
			if _, exists := validator.sourceRefIDs[ref.SourceRefID]; exists {
				validator.fail("source_ref.duplicate_id", ref.SourceRefID)
			} else {
				validator.sourceRefIDs[ref.SourceRefID] = struct{}{}
			}
			if ref.SourceRefKind == "path_digest" && ref.RecordedSourceDigest != ref.CurrentSourceDigest {
				validator.fail("source_ref.stale_digest", ref.SourceRefID)
				validator.staleSourceRefIDs = append(validator.staleSourceRefIDs, ref.SourceRefID)
			}
		}
	}
	if _, ok := validator.nodeByID[input.RootNodeID]; !ok {
		validator.fail("topology.missing_root", input.RootNodeID)
	}
}

func (validator *treeValidator) indexEdges(input admittedInput) {
	seen := map[string]struct{}{}
	for _, item := range input.Edges {
		key := item.ParentNodeID + "->" + item.ChildNodeID
		if _, exists := seen[key]; exists {
			validator.fail("topology.duplicate_edge", key)
			continue
		}
		seen[key] = struct{}{}
		if _, ok := validator.nodeByID[item.ParentNodeID]; !ok {
			validator.fail("topology.missing_edge_parent", item.ParentNodeID)
		}
		if _, ok := validator.nodeByID[item.ChildNodeID]; !ok {
			validator.fail("topology.missing_edge_child", item.ChildNodeID)
		}
		validator.childrenByParent[item.ParentNodeID] = append(validator.childrenByParent[item.ParentNodeID], item.ChildNodeID)
		validator.parentByChild[item.ChildNodeID] = append(validator.parentByChild[item.ChildNodeID], item.ParentNodeID)
	}
	for parentID := range validator.childrenByParent {
		sort.Strings(validator.childrenByParent[parentID])
	}
}

func (validator *treeValidator) validateTopology(input admittedInput) {
	for nodeID := range validator.nodeByID {
		parentCount := len(validator.parentByChild[nodeID])
		if nodeID == input.RootNodeID {
			if parentCount > 0 {
				validator.fail("topology.root_has_parent", nodeID)
			}
			continue
		}
		switch {
		case parentCount == 0:
			validator.fail("topology.missing_parent", nodeID)
		case parentCount > 1:
			validator.fail("topology.multi_parent", nodeID)
		}
	}
	validator.validateSiblingOrder()
	validator.detectCycles()
	if _, ok := validator.nodeByID[input.RootNodeID]; ok {
		validator.visited = map[string]int{}
		validator.visiting = map[string]struct{}{}
		validator.walk(input.RootNodeID, 1)
		for nodeID := range validator.nodeByID {
			if _, ok := validator.visited[nodeID]; !ok {
				validator.fail("topology.unreachable_node", nodeID)
			}
		}
	}
}

func (validator *treeValidator) detectCycles() {
	color := map[string]int{}
	stack := map[string]struct{}{}
	nodeIDs := make([]string, 0, len(validator.nodeByID))
	for nodeID := range validator.nodeByID {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	for _, nodeID := range nodeIDs {
		validator.detectCycleFrom(nodeID, color, stack, 1)
	}
}

func (validator *treeValidator) detectCycleFrom(nodeID string, color map[string]int, stack map[string]struct{}, depth int) {
	if depth > maxSpecTreeDepth {
		validator.fail("topology.depth_limit", nodeID)
		return
	}
	if color[nodeID] == 2 {
		return
	}
	if color[nodeID] == 1 {
		if _, ok := stack[nodeID]; ok {
			validator.fail("topology.cycle", nodeID)
		}
		return
	}
	color[nodeID] = 1
	stack[nodeID] = struct{}{}
	for _, childID := range validator.childrenByParent[nodeID] {
		if _, ok := validator.nodeByID[childID]; ok {
			validator.detectCycleFrom(childID, color, stack, depth+1)
		}
	}
	delete(stack, nodeID)
	color[nodeID] = 2
}

func (validator *treeValidator) validateSiblingOrder() {
	for parentID, childIDs := range validator.childrenByParent {
		orders := map[int]string{}
		for _, childID := range childIDs {
			child, ok := validator.nodeByID[childID]
			if !ok {
				continue
			}
			if existing, exists := orders[child.DisplayOrder]; exists {
				validator.fail("topology.sibling_display_order_collision", parentID+":"+existing+":"+childID)
				continue
			}
			orders[child.DisplayOrder] = childID
		}
	}
}

func (validator *treeValidator) walk(nodeID string, depth int) {
	if depth > maxSpecTreeDepth {
		validator.fail("topology.depth_limit", nodeID)
		return
	}
	if _, ok := validator.visiting[nodeID]; ok {
		validator.fail("topology.cycle", nodeID)
		return
	}
	if previousDepth, ok := validator.visited[nodeID]; ok {
		if depth < previousDepth {
			validator.visited[nodeID] = depth
		}
		return
	}
	validator.visiting[nodeID] = struct{}{}
	validator.visited[nodeID] = depth
	if depth > validator.maxDepth {
		validator.maxDepth = depth
	}
	for _, childID := range validator.childrenByParent[nodeID] {
		validator.walk(childID, depth+1)
	}
	delete(validator.visiting, nodeID)
}

func (validator *treeValidator) validateOverlays(input admittedInput) {
	seen := map[string]struct{}{}
	for _, item := range input.Overlays {
		if _, exists := seen[item.OverlayID]; exists {
			validator.fail("overlay.duplicate_id", item.OverlayID)
		}
		seen[item.OverlayID] = struct{}{}
		if _, ok := validator.nodeByID[item.TargetNodeID]; !ok {
			validator.fail("overlay.unknown_target_node", item.OverlayID+":"+item.TargetNodeID)
		}
		if item.RefKind == "source_ref" {
			if _, ok := validator.sourceRefIDs[item.RefID]; !ok {
				validator.fail("overlay.unknown_source_ref", item.OverlayID+":"+item.RefID)
			}
		}
	}
}

func (validator *treeValidator) fail(rule string, value string) {
	validator.failures = append(validator.failures, fmt.Sprintf("%s:%s", rule, value))
}

func (validator *treeValidator) sort() {
	sort.Strings(validator.failures)
	validator.failures = uniqueSorted(validator.failures)
	sort.Strings(validator.staleSourceRefIDs)
	validator.staleSourceRefIDs = uniqueSorted(validator.staleSourceRefIDs)
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for index := 1; index < len(values); index++ {
		if values[index] != result[len(result)-1] {
			result = append(result, values[index])
		}
	}
	return result
}
