package requirementcontext

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maxOperationBytes = 24 << 20

type SliceQuery struct {
	MaxDepth        *int
	MaxNodes        int
	MaxRequirements int
	NodeIDs         []string
	OwnerIDs        []string
	Profile         string
	RequirementIDs  []string
	LifecycleStates []string
}

type nodeSelection struct {
	maxDepthOmitted int
	maxNodesOmitted int
	selected        map[string]struct{}
	sourceIDs       map[string]struct{}
}

func Slice(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement context slice input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"context", "query", "schemaVersion", "sliceId"}, "requirement context slice input"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, fmt.Errorf("requirement context slice schemaVersion must be 1")
	}
	sliceID, err := admit.RuleID(record["sliceId"], "requirement context sliceId")
	if err != nil {
		return nil, err
	}
	snapshot, err := AdmitSnapshot(record["context"])
	if err != nil {
		return nil, err
	}
	query, err := admitSliceQuery(record["query"])
	if err != nil {
		return nil, err
	}
	output, err := buildSlice(sliceID, snapshot, query)
	if err != nil {
		return nil, err
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxOperationBytes {
		return nil, fmt.Errorf("requirement context slice exceeds byte limit")
	}
	return output, nil
}

func buildSlice(sliceID string, snapshot Snapshot, query SliceQuery) (map[string]any, error) {
	if err := validateSelectorVocabulary(snapshot.RequirementSources, query); err != nil {
		return nil, err
	}
	nodeResult, err := selectNodes(snapshot.Tree, query)
	if err != nil {
		return nil, err
	}
	selectedNodes := nodeResult.selected
	treeScopeActive := len(query.NodeIDs) > 0 || query.Profile == "routing"
	selectedSources, selectedRequirements, omittedRequirements, requirementSet, selectedSourceIDs, err := selectRequirements(snapshot.RequirementSources, nodeResult.sourceIDs, treeScopeActive, query)
	if err != nil {
		return nil, err
	}
	if !treeScopeActive && len(selectedSourceIDs) > 0 {
		derived := query
		depth := 0
		derived.MaxDepth = &depth
		derived.NodeIDs = sourceNodeIDs(snapshot.Sources, selectedSourceIDs)
		nodeResult, err = selectNodes(snapshot.Tree, derived)
		if err != nil {
			return nil, err
		}
		// The derived depth-zero scope requests source nodes and their ancestors;
		// descendants were never part of the caller's selection domain.
		nodeResult.maxDepthOmitted = 0
		nodeResult.maxNodesOmitted = 0
		selectedNodes = nodeResult.selected
	}
	projections := map[string]any{
		"requirementSources": requirementSourceFragmentValues(snapshot.RequirementSources, selectedSources),
		"specTree":           treeSliceValue(snapshot.Tree, selectedNodes, selectedSourceIDs),
	}
	if query.Profile == "proof" || query.Profile == "review" {
		if snapshot.ProofBinding != nil {
			projections["proofBinding"] = requirementbinding.SelectionFragmentValue(*snapshot.ProofBinding, requirementSet)
		}
	}
	if query.Profile == "coverage" || query.Profile == "review" {
		if snapshot.Coverage != nil {
			projections["coverage"] = requirementcoverageview.SelectRequirements(snapshot.Coverage, requirementSet)
		}
	}
	state := "selected"
	if selectedRequirements == 0 && len(selectedNodes) == 0 {
		state = "no_match"
	}
	omissions := []any{}
	if nodeResult.maxDepthOmitted > 0 {
		omissions = append(omissions, map[string]any{"count": nodeResult.maxDepthOmitted, "kind": "nodes", "reason": "max_depth"})
	}
	if nodeResult.maxNodesOmitted > 0 {
		omissions = append(omissions, map[string]any{"count": nodeResult.maxNodesOmitted, "kind": "nodes", "reason": "max_nodes"})
	}
	if omittedRequirements > 0 {
		omissions = append(omissions, map[string]any{"count": omittedRequirements, "kind": "requirements", "reason": "max_requirements"})
	}
	return map[string]any{
		"contextKind":   "proofkit.requirement-context-slice",
		"nonClaims":     admit.StringSliceToAny(boundaryNonClaims),
		"omissions":     omissions,
		"profile":       query.Profile,
		"projections":   projections,
		"schemaVersion": json.Number("1"),
		"sliceId":       sliceID,
		"snapshotId":    snapshot.SnapshotID,
		"state":         state,
	}, nil
}

func selectNodes(tree requirementspectree.Tree, query SliceQuery) (nodeSelection, error) {
	nodeByID := map[string]requirementspectree.Node{}
	children := map[string][]string{}
	parents := map[string]string{}
	for _, node := range tree.Nodes {
		nodeByID[node.NodeID] = node
	}
	for _, edge := range tree.Edges {
		children[edge.ParentNodeID] = append(children[edge.ParentNodeID], edge.ChildNodeID)
		parents[edge.ChildNodeID] = edge.ParentNodeID
	}
	for parentID := range children {
		sort.Slice(children[parentID], func(left, right int) bool {
			leftNode := nodeByID[children[parentID][left]]
			rightNode := nodeByID[children[parentID][right]]
			if leftNode.DisplayOrder != rightNode.DisplayOrder {
				return leftNode.DisplayOrder < rightNode.DisplayOrder
			}
			return leftNode.NodeID < rightNode.NodeID
		})
	}
	roots := query.NodeIDs
	if len(roots) == 0 && query.Profile == "routing" {
		roots = []string{tree.RootNodeID}
	}
	fullReachable := map[string]struct{}{}
	depthEligible := map[string]struct{}{}
	queue := []struct {
		id    string
		depth int
	}{}
	for _, id := range roots {
		if _, ok := nodeByID[id]; !ok {
			return nodeSelection{}, fmt.Errorf("requirement context slice references unknown node")
		}
		queue = append(queue, struct {
			id    string
			depth int
		}{id, 0})
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if _, exists := fullReachable[item.id]; exists {
			continue
		}
		fullReachable[item.id] = struct{}{}
		if query.MaxDepth == nil || item.depth <= *query.MaxDepth {
			depthEligible[item.id] = struct{}{}
		}
		for _, child := range children[item.id] {
			queue = append(queue, struct {
				id    string
				depth int
			}{child, item.depth + 1})
		}
	}
	selected := map[string]struct{}{}
	for _, id := range roots {
		for current := id; current != ""; current = parents[current] {
			selected[current] = struct{}{}
		}
	}
	if len(selected) > query.MaxNodes {
		return nodeSelection{}, fmt.Errorf("requirement context slice maxNodes cannot retain mandatory ancestor closure")
	}
	for _, id := range parentBeforeChildOrder(tree.RootNodeID, children) {
		if len(selected) >= query.MaxNodes {
			break
		}
		if _, ok := depthEligible[id]; ok {
			selected[id] = struct{}{}
		}
	}
	maxDepthOmitted := 0
	for id := range fullReachable {
		if _, ok := depthEligible[id]; !ok {
			maxDepthOmitted++
		}
	}
	maxNodesOmitted := 0
	for id := range depthEligible {
		if _, ok := selected[id]; !ok {
			maxNodesOmitted++
		}
	}
	sourceIDs := map[string]struct{}{}
	for id := range selected {
		for _, ref := range nodeByID[id].SourceRefs {
			if ref.SourceRole == "requirements" && ref.SourceID != "" {
				sourceIDs[ref.SourceID] = struct{}{}
			}
		}
	}
	return nodeSelection{maxDepthOmitted: maxDepthOmitted, maxNodesOmitted: maxNodesOmitted, selected: selected, sourceIDs: sourceIDs}, nil
}

func parentBeforeChildOrder(rootID string, children map[string][]string) []string {
	ordered := []string{}
	queue := []string{rootID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		ordered = append(ordered, id)
		queue = append(queue, children[id]...)
	}
	return ordered
}

func selectRequirements(values []requirementsourceadmission.Source, sourceIDs map[string]struct{}, treeScopeActive bool, query SliceQuery) ([]requirementsourceadmission.Source, int, int, map[string]struct{}, map[string]struct{}, error) {
	requirementFilter := stringSet(query.RequirementIDs)
	ownerFilter := stringSet(query.OwnerIDs)
	lifecycleFilter := stringSet(query.LifecycleStates)
	selectedSources := []requirementsourceadmission.Source{}
	selectedSourceIDs := map[string]struct{}{}
	selectedIDs := map[string]struct{}{}
	knownIDs := map[string]struct{}{}
	type location struct {
		requirement requirementsourceadmission.Requirement
		sourceIndex int
	}
	locations := map[string]location{}
	candidates := []string{}
	eligibleIDs := map[string]struct{}{}
	for sourceIndex, source := range values {
		_, selectedByNode := sourceIDs[source.SourceID]
		for _, requirement := range source.Requirements {
			id := requirement.RequirementID
			knownIDs[id] = struct{}{}
			locations[id] = location{requirement: requirement, sourceIndex: sourceIndex}
			owner := requirement.OwnerID
			lifecycle := requirement.Lifecycle.State
			if !selectedByNode && treeScopeActive {
				continue
			}
			if len(requirementFilter) > 0 {
				if _, ok := requirementFilter[id]; !ok {
					continue
				}
			}
			if len(ownerFilter) > 0 {
				if _, ok := ownerFilter[owner]; !ok {
					continue
				}
			}
			if len(lifecycleFilter) > 0 {
				if _, ok := lifecycleFilter[lifecycle]; !ok {
					continue
				}
			}
			candidates = append(candidates, id)
			eligibleIDs[id] = struct{}{}
		}
	}
	for _, id := range query.RequirementIDs {
		if _, ok := knownIDs[id]; !ok {
			return nil, 0, 0, nil, nil, fmt.Errorf("requirement context slice references unknown requirement")
		}
	}
	initialCount := len(candidates)
	if initialCount > query.MaxRequirements {
		initialCount = query.MaxRequirements
	}
	for _, id := range candidates[:initialCount] {
		selectedIDs[id] = struct{}{}
	}
	for _, id := range query.RequirementIDs {
		if _, eligible := eligibleIDs[id]; eligible {
			if _, selected := selectedIDs[id]; !selected {
				return nil, 0, 0, nil, nil, fmt.Errorf("requirement context slice maxRequirements cannot retain all explicit requirements")
			}
		}
	}
	queue := make([]string, 0, len(selectedIDs))
	for id := range selectedIDs {
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, replacementID := range locations[id].requirement.Lifecycle.ReplacementRequirementIDs {
			if _, ok := locations[replacementID]; !ok {
				return nil, 0, 0, nil, nil, fmt.Errorf("requirement context slice lifecycle reference does not resolve")
			}
			if _, exists := selectedIDs[replacementID]; exists {
				continue
			}
			if len(selectedIDs) >= query.MaxRequirements {
				return nil, 0, 0, nil, nil, fmt.Errorf("requirement context slice maxRequirements cannot retain mandatory lifecycle closure")
			}
			selectedIDs[replacementID] = struct{}{}
			queue = append(queue, replacementID)
		}
	}
	omitted := 0
	for _, id := range candidates {
		if _, selected := selectedIDs[id]; !selected {
			omitted++
		}
	}
	for sourceIndex, source := range values {
		selected := []requirementsourceadmission.Requirement{}
		for _, requirement := range source.Requirements {
			if _, ok := selectedIDs[requirement.RequirementID]; ok && locations[requirement.RequirementID].sourceIndex == sourceIndex {
				selected = append(selected, requirement)
			}
		}
		if len(selected) == 0 {
			continue
		}
		copySource := source
		copySource.Requirements = selected
		selectedSources = append(selectedSources, copySource)
		selectedSourceIDs[source.SourceID] = struct{}{}
	}
	return selectedSources, len(selectedIDs), omitted, selectedIDs, selectedSourceIDs, nil
}

func treeSliceValue(tree requirementspectree.Tree, selected, selectedSourceIDs map[string]struct{}) map[string]any {
	value := requirementspectree.TreeValue(tree)
	nodes := []any{}
	retainedSourceRefs := map[string]struct{}{}
	for _, raw := range value["nodes"].([]any) {
		node := raw.(map[string]any)
		if _, ok := selected[node["nodeId"].(string)]; ok {
			refs := []any{}
			for _, rawRef := range node["sourceRefs"].([]any) {
				ref := rawRef.(map[string]any)
				if ref["sourceRole"] == "requirements" && ref["sourceRefKind"] == "source_id" {
					if _, ok := selectedSourceIDs[ref["sourceId"].(string)]; !ok {
						continue
					}
				}
				refID, ok := ref["sourceRefId"].(string)
				if !ok {
					continue
				}
				refs = append(refs, ref)
				retainedSourceRefs[refID] = struct{}{}
			}
			node["sourceRefs"] = refs
			nodes = append(nodes, node)
		}
	}
	edges := []any{}
	for _, raw := range value["edges"].([]any) {
		edge := raw.(map[string]any)
		_, parent := selected[edge["parentNodeId"].(string)]
		_, child := selected[edge["childNodeId"].(string)]
		if parent && child {
			edges = append(edges, edge)
		}
	}
	overlays := []any{}
	for _, raw := range value["overlays"].([]any) {
		overlay := raw.(map[string]any)
		if _, ok := selected[overlay["targetNodeId"].(string)]; !ok {
			continue
		}
		if overlay["refKind"] == "source_ref" {
			if _, ok := retainedSourceRefs[overlay["refId"].(string)]; !ok {
				continue
			}
		}
		overlays = append(overlays, overlay)
	}
	value["nodes"] = nodes
	value["edges"] = edges
	value["overlays"] = overlays
	value["authority"] = "lookup_fragment_only"
	value["projectionKind"] = "proofkit.requirement-spec-tree-fragment"
	value["sourceTreeId"] = value["treeId"]
	delete(value, "treeId")
	if len(nodes) == 0 {
		value["rootNodeId"] = nil
	}
	return value
}

func requirementSourceFragmentValues(all, selected []requirementsourceadmission.Source) []any {
	totals := map[string]int{}
	for _, source := range all {
		totals[source.SourceID] = len(source.Requirements)
	}
	values := make([]any, 0, len(selected))
	for _, source := range selected {
		requirements := make([]any, 0, len(source.Requirements))
		for _, requirement := range source.Requirements {
			requirements = append(requirements, requirementsourceadmission.RequirementValue(requirement))
		}
		values = append(values, map[string]any{
			"authority": "lookup_fragment_only", "omittedRequirementCount": totals[source.SourceID] - len(source.Requirements),
			"projectionKind": "proofkit.requirement-source-fragment", "requirements": requirements,
			"selectedRequirementCount": len(source.Requirements), "sourceId": source.SourceID,
			"totalRequirementCount": totals[source.SourceID],
		})
	}
	return values
}

func stringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sourceNodeIDs(sources []Source, selectedSourceIDs map[string]struct{}) []string {
	result := []string{}
	for _, source := range sources {
		if source.Kind != "requirement_source" {
			continue
		}
		if _, ok := selectedSourceIDs[source.SourceRef]; ok {
			result = append(result, source.NodeID)
		}
	}
	return result

}

func validateSelectorVocabulary(sources []requirementsourceadmission.Source, query SliceQuery) error {
	knownOwners := map[string]struct{}{}
	knownLifecycles := map[string]struct{}{}
	for _, source := range sources {
		for _, requirement := range source.Requirements {
			knownOwners[requirement.OwnerID] = struct{}{}
			knownLifecycles[requirement.Lifecycle.State] = struct{}{}
		}
	}
	for _, ownerID := range query.OwnerIDs {
		if _, ok := knownOwners[ownerID]; !ok {
			return fmt.Errorf("requirement context slice references unknown owner")
		}
	}
	for _, lifecycle := range query.LifecycleStates {
		if _, ok := knownLifecycles[lifecycle]; !ok {
			return fmt.Errorf("requirement context slice references unavailable lifecycle state")
		}
	}
	return nil
}
