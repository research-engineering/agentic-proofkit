package requirementgraph

// NodeReference identifies a graph-node pointer, not a source or witness ID.
type NodeReference struct {
	RecordKind   string
	RecordID     string
	Field        string
	TargetNodeID string
}

// NodeReferences projects known pointer fields from records selected from an
// owner-admitted output. It neither re-admits a partial graph nor creates edges.
func NodeReferences(nodes, edges []any) []NodeReference {
	refs := make([]NodeReference, 0)
	for _, raw := range nodes {
		node := raw.(map[string]any)
		if parent, present := node["parentNodeId"]; present {
			refs = append(refs, NodeReference{"node", node["nodeId"].(string), "parentNodeId", parent.(string)})
		}
	}
	for _, raw := range edges {
		edge := raw.(map[string]any)
		for _, field := range []string{"codeNodeId", "fromNodeId", "toNodeId"} {
			if target, present := edge[field]; present {
				refs = append(refs, NodeReference{"edge", edge["edgeId"].(string), field, target.(string)})
			}
		}
	}
	return refs
}
