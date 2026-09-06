package requirementbrowser

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type workspaceNavigationQuery struct {
	ParentNodeID string
	Offset       int
	MaxRecords   int
}

func admitWorkspaceNavigationQuery(raw any, index workspaceLookupIndex) (workspaceNavigationQuery, error) {
	query := workspaceNavigationQuery{MaxRecords: 64}
	if raw == nil {
		return query, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return workspaceNavigationQuery{}, fmt.Errorf("browser navigation query must be an object")
	}
	if err := admit.KnownKeys(record, []string{"maxRecords", "offset", "parentNodeId"}, "browser navigation query"); err != nil {
		return workspaceNavigationQuery{}, err
	}
	var err error
	if raw, present := record["parentNodeId"]; present {
		query.ParentNodeID, err = admit.RuleID(raw, "browser navigation parentNodeId")
		if err != nil {
			return workspaceNavigationQuery{}, err
		}
		if _, ok := index.Nodes[query.ParentNodeID]; !ok {
			return workspaceNavigationQuery{}, fmt.Errorf("browser navigation parent is unknown")
		}
	}
	if raw, present := record["offset"]; present {
		query.Offset, err = nonNegativeJSONInteger(raw, "browser navigation offset")
		if err != nil {
			return workspaceNavigationQuery{}, err
		}
	}
	if raw, present := record["maxRecords"]; present {
		query.MaxRecords, err = positiveJSONInteger(raw, "browser navigation maxRecords")
		if err != nil || query.MaxRecords > 128 {
			return workspaceNavigationQuery{}, fmt.Errorf("browser navigation maxRecords must be between 1 and 128")
		}
	}
	return query, nil
}

func workspaceNavigationPage(index workspaceLookupIndex, query workspaceNavigationQuery) workspacePage {
	nodes := []string{index.RootNodeID}
	var parent any
	if query.ParentNodeID != "" {
		nodes = index.Children[query.ParentNodeID]
		parent = index.navigationNodeValue(query.ParentNodeID)
	}
	return workspacePage{
		Count: len(nodes), Offset: query.Offset, Limit: query.MaxRecords, RowsKey: "nodes",
		Row: func(position int) map[string]any { return index.navigationNodeValue(nodes[position]) },
		Projection: func(rows []any) (map[string]any, string) {
			state := "complete"
			if len(rows) != len(nodes) {
				state = "partial_with_omissions"
			}
			return map[string]any{
				"authority": "lookup_fragment_only", "projectionKind": "proofkit.requirement-browser-navigation-fragment",
				"parent": parent, "nodes": rows, "availableNodeCount": len(nodes), "selectedNodeCount": len(rows), "omittedNodeCount": len(nodes) - len(rows),
			}, state
		},
	}
}

func (index workspaceLookupIndex) navigationNodeValue(nodeID string) map[string]any {
	node := index.Nodes[nodeID]
	return map[string]any{"nodeId": node.NodeID, "nodeKind": node.NodeKind, "label": node.Label, "childCount": len(index.Children[nodeID])}
}
