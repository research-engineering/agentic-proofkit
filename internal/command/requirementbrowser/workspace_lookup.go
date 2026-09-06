package requirementbrowser

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	maxWorkspaceSearchBytes = 1024
	maxWorkspaceSearchRunes = 256
)

type workspaceRequirement struct {
	Anchor          workspaceAnchor
	Requirement     requirementsourceadmission.Requirement
	SearchFields    [3]string
	SourceID        string
	SourceNonClaims []string
}

type workspaceLookupIndex struct {
	Rows            []workspaceRequirement
	Nodes           map[string]requirementspectree.Node
	Children        map[string][]string
	SourcesByNode   map[string][]string
	Owners          map[string]struct{}
	LifecycleStates map[string]struct{}
	RootNodeID      string
}

type workspaceLookupQuery struct {
	Page           projectionQuery
	SearchText     string
	NodeID         string
	OwnerID        string
	LifecycleState string
}

func buildWorkspaceLookupIndex(snapshot requirementcontext.Snapshot) (workspaceLookupIndex, map[string]workspaceAnchor) {
	index := workspaceLookupIndex{
		Nodes: map[string]requirementspectree.Node{}, Children: map[string][]string{},
		SourcesByNode: map[string][]string{}, Owners: map[string]struct{}{},
		LifecycleStates: map[string]struct{}{}, RootNodeID: snapshot.Tree.RootNodeID,
	}
	digests := map[string]string{}
	for _, source := range snapshot.Sources {
		if source.Kind == "requirement_source" {
			digests[source.SourceRef] = source.CurrentDigest
		}
	}
	anchors := map[string]workspaceAnchor{}
	// The snapshot owner orders both typed sources and their wire projection.
	for sourceIndex, source := range snapshot.RequirementSources {
		for requirementIndex, requirement := range source.Requirements {
			anchor := workspaceAnchor{
				AnchorID:      "requirement:" + requirement.RequirementID + ":invariant",
				JSONPointer:   fmt.Sprintf("/projections/requirementSources/%d/requirements/%d/invariant", sourceIndex, requirementIndex),
				RequirementID: requirement.RequirementID, SourceDigest: digests[source.SourceID], Text: requirement.Invariant,
			}
			anchors[anchor.AnchorID] = anchor
			index.Rows = append(index.Rows, workspaceRequirement{
				Anchor: anchor, Requirement: requirement, SourceID: source.SourceID, SourceNonClaims: source.NonClaims,
				SearchFields: [3]string{strings.ToLower(requirement.RequirementID), strings.ToLower(requirement.OwnerID), strings.ToLower(requirement.Invariant)},
			})
			index.Owners[requirement.OwnerID] = struct{}{}
			index.LifecycleStates[requirement.Lifecycle.State] = struct{}{}
		}
	}
	sort.Slice(index.Rows, func(a, b int) bool {
		return index.Rows[a].Requirement.RequirementID < index.Rows[b].Requirement.RequirementID
	})
	for _, node := range snapshot.Tree.Nodes {
		index.Nodes[node.NodeID] = node
		for _, ref := range node.SourceRefs {
			if ref.SourceRefKind == "source_id" && ref.SourceRole == "requirements" {
				index.SourcesByNode[node.NodeID] = append(index.SourcesByNode[node.NodeID], ref.SourceID)
			}
		}
	}
	for _, edge := range snapshot.Tree.Edges {
		index.Children[edge.ParentNodeID] = append(index.Children[edge.ParentNodeID], edge.ChildNodeID)
	}
	for _, children := range index.Children {
		sort.Slice(children, func(a, b int) bool {
			left, right := index.Nodes[children[a]], index.Nodes[children[b]]
			if left.DisplayOrder != right.DisplayOrder {
				return left.DisplayOrder < right.DisplayOrder
			}
			return left.NodeID < right.NodeID
		})
	}
	return index, anchors
}

func admitWorkspaceLookupQuery(raw any, index workspaceLookupIndex) (workspaceLookupQuery, error) {
	if raw == nil {
		page, _ := admitProjectionQuery(nil)
		return workspaceLookupQuery{Page: page}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return workspaceLookupQuery{}, fmt.Errorf("browser lookup query must be an object")
	}
	if err := admit.KnownKeys(record, []string{"edgeOffset", "lifecycleState", "maxEdges", "maxRecords", "nodeId", "offset", "ownerId", "searchText"}, "browser lookup query"); err != nil {
		return workspaceLookupQuery{}, err
	}
	numeric := map[string]any{}
	for _, key := range []string{"edgeOffset", "maxEdges", "maxRecords", "offset"} {
		if value, present := record[key]; present {
			numeric[key] = value
		}
	}
	page, err := admitProjectionQuery(numeric)
	if err != nil {
		return workspaceLookupQuery{}, err
	}
	query := workspaceLookupQuery{Page: page}
	if rawSearch, present := record["searchText"]; present {
		text, ok := rawSearch.(string)
		if !ok || len(text) > maxWorkspaceSearchBytes || !utf8.ValidString(text) || utf8.RuneCountInString(text) > maxWorkspaceSearchRunes {
			return workspaceLookupQuery{}, fmt.Errorf("browser search text exceeds its type or size contract")
		}
		text = strings.TrimSpace(text)
		if text != "" {
			if _, err := admit.NonEmptyText(text, "browser search text"); err != nil {
				return workspaceLookupQuery{}, err
			}
		}
		query.SearchText = strings.ToLower(text)
	}
	for _, field := range []struct {
		key    string
		target *string
	}{{"nodeId", &query.NodeID}, {"ownerId", &query.OwnerID}} {
		if raw, present := record[field.key]; present {
			*field.target, err = admit.RuleID(raw, "browser lookup "+field.key)
			if err != nil {
				return workspaceLookupQuery{}, err
			}
		}
	}
	if query.NodeID != "" {
		if _, ok := index.Nodes[query.NodeID]; !ok {
			return workspaceLookupQuery{}, fmt.Errorf("browser lookup node is unknown")
		}
	}
	if query.OwnerID != "" {
		if _, ok := index.Owners[query.OwnerID]; !ok {
			return workspaceLookupQuery{}, fmt.Errorf("browser lookup owner is unknown")
		}
	}
	if raw, present := record["lifecycleState"]; present {
		query.LifecycleState, err = requirementsourceadmission.AdmitLifecycleState(raw, "browser lookup lifecycleState")
		if err != nil {
			return workspaceLookupQuery{}, err
		}
	}
	return query, nil
}

func (index workspaceLookupIndex) matchingRequirements(query workspaceLookupQuery) []int {
	var sources map[string]struct{}
	if query.NodeID != "" {
		sources = map[string]struct{}{}
		pending := []string{query.NodeID}
		for len(pending) > 0 {
			nodeID := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			for _, sourceID := range index.SourcesByNode[nodeID] {
				sources[sourceID] = struct{}{}
			}
			pending = append(pending, index.Children[nodeID]...)
		}
	}
	matches := []int{}
	for position, row := range index.Rows {
		if sources != nil {
			if _, ok := sources[row.SourceID]; !ok {
				continue
			}
		}
		if query.OwnerID != "" && row.Requirement.OwnerID != query.OwnerID || query.LifecycleState != "" && row.Requirement.Lifecycle.State != query.LifecycleState {
			continue
		}
		if query.SearchText != "" && !strings.Contains(row.SearchFields[0], query.SearchText) && !strings.Contains(row.SearchFields[1], query.SearchText) && !strings.Contains(row.SearchFields[2], query.SearchText) {
			continue
		}
		matches = append(matches, position)
	}
	return matches
}

func (row workspaceRequirement) value() map[string]any {
	return map[string]any{
		"anchor": anchorValue(row.Anchor), "claimLevel": row.Requirement.ClaimLevel,
		"invariant": row.Requirement.Invariant, "lifecycleState": row.Requirement.Lifecycle.State,
		"nonClaims": admit.StringSliceToAny(row.Requirement.NonClaims), "ownerId": row.Requirement.OwnerID,
		"requirementId": row.Requirement.RequirementID, "sourceNonClaims": admit.StringSliceToAny(row.SourceNonClaims),
	}
}

func workspaceLookupPage(index workspaceLookupIndex, query workspaceLookupQuery) workspacePage {
	return workspaceRequirementPage(index, index.matchingRequirements(query), query.Page)
}

func workspaceRequirementPage(index workspaceLookupIndex, matches []int, query projectionQuery) workspacePage {
	return workspacePage{
		Count: len(matches), Offset: query.Offset, Limit: query.MaxRecords, RowsKey: "requirements",
		Row: func(position int) map[string]any { return index.Rows[matches[position]].value() },
		Projection: func(rows []any) (map[string]any, string) {
			state := "complete"
			if len(rows) != len(index.Rows) {
				state = "partial_with_omissions"
			}
			return map[string]any{
				"authority": "lookup_fragment_only", "projectionKind": "proofkit.requirement-browser-requirement-fragment",
				"availableRequirementCount": len(index.Rows), "matchingRequirementCount": len(matches), "selectedRequirementCount": len(rows),
				"filteredOutRequirementCount": len(index.Rows) - len(matches), "pageOmittedRequirementCount": len(matches) - len(rows),
				"omittedRequirementCount": len(index.Rows) - len(rows), "requirements": rows,
			}, state
		},
	}
}

func workspaceSortedSet(values map[string]struct{}) []any {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return admit.StringSliceToAny(keys)
}
