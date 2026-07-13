package requirementgraph

import "fmt"

type outputTopologyNode struct {
	id       string
	kind     string
	parentID string
	plane    string
}

type outputTopologyEdge struct {
	codeNodeID string
	fromID     string
	id         string
	kind       string
	plane      string
	toID       string
}

type outputTopology struct {
	edges []outputTopologyEdge
	nodes []outputTopologyNode
}

func outputTopologyFromRecords(nodes, edges []map[string]any) (outputTopology, error) {
	topology := outputTopology{
		edges: make([]outputTopologyEdge, 0, len(edges)),
		nodes: make([]outputTopologyNode, 0, len(nodes)),
	}
	for index, record := range nodes {
		id, err := outputTopologyString(record["nodeId"], fmt.Sprintf("requirement traceability graph nodes[%d] nodeId", index))
		if err != nil {
			return outputTopology{}, err
		}
		kind, err := outputTopologyString(record["kind"], fmt.Sprintf("requirement traceability graph nodes[%d] kind", index))
		if err != nil {
			return outputTopology{}, err
		}
		plane, err := outputTopologyString(record["evidencePlane"], fmt.Sprintf("requirement traceability graph nodes[%d] evidencePlane", index))
		if err != nil {
			return outputTopology{}, err
		}
		parentID := ""
		if rawParentID, exists := record["parentNodeId"]; exists {
			parentID, err = outputTopologyString(rawParentID, fmt.Sprintf("requirement traceability graph nodes[%d] parentNodeId", index))
			if err != nil {
				return outputTopology{}, err
			}
		}
		topology.nodes = append(topology.nodes, outputTopologyNode{id: id, kind: kind, parentID: parentID, plane: plane})
	}
	for index, record := range edges {
		id, err := outputTopologyString(record["edgeId"], fmt.Sprintf("requirement traceability graph edges[%d] edgeId", index))
		if err != nil {
			return outputTopology{}, err
		}
		fromID, err := outputTopologyString(record["fromNodeId"], fmt.Sprintf("requirement traceability graph edges[%d] fromNodeId", index))
		if err != nil {
			return outputTopology{}, err
		}
		toID, err := outputTopologyString(record["toNodeId"], fmt.Sprintf("requirement traceability graph edges[%d] toNodeId", index))
		if err != nil {
			return outputTopology{}, err
		}
		kind, err := outputTopologyString(record["edgeKind"], fmt.Sprintf("requirement traceability graph edges[%d] edgeKind", index))
		if err != nil {
			return outputTopology{}, err
		}
		plane, err := outputTopologyString(record["evidencePlane"], fmt.Sprintf("requirement traceability graph edges[%d] evidencePlane", index))
		if err != nil {
			return outputTopology{}, err
		}
		codeNodeID := ""
		if rawCodeNodeID, exists := record["codeNodeId"]; exists {
			codeNodeID, err = outputTopologyString(rawCodeNodeID, fmt.Sprintf("requirement traceability graph edges[%d] codeNodeId", index))
			if err != nil {
				return outputTopology{}, err
			}
		}
		topology.edges = append(topology.edges, outputTopologyEdge{codeNodeID: codeNodeID, fromID: fromID, id: id, kind: kind, plane: plane, toID: toID})
	}
	return topology, nil
}

func validateOutputTopology(topology outputTopology) error {
	nodesByID := make(map[string]outputTopologyNode, len(topology.nodes))
	for _, node := range topology.nodes {
		if _, exists := nodesByID[node.id]; exists {
			return fmt.Errorf("requirement traceability graph node ids must be unique")
		}
		nodesByID[node.id] = node
	}
	seenEdges := make(map[string]struct{}, len(topology.edges))
	codeParentsByChild := map[string]string{}
	for _, edge := range topology.edges {
		if _, exists := seenEdges[edge.id]; exists {
			return fmt.Errorf("requirement traceability graph edge ids must be unique")
		}
		seenEdges[edge.id] = struct{}{}
		from, fromExists := nodesByID[edge.fromID]
		if !fromExists {
			return fmt.Errorf("requirement traceability graph edge source must resolve")
		}
		to, toExists := nodesByID[edge.toID]
		if !toExists {
			return fmt.Errorf("requirement traceability graph edge target must resolve")
		}
		if !validOutputTopologyRelation(edge, from, to, nodesByID) {
			return fmt.Errorf("requirement traceability graph relation is incompatible with its evidence plane and endpoint kinds")
		}
		if edge.plane == "code_traceability" && edge.kind == "contains" {
			if _, exists := codeParentsByChild[edge.toID]; exists {
				return fmt.Errorf("requirement traceability graph code node must have exactly one parent edge")
			}
			codeParentsByChild[edge.toID] = edge.fromID
		}
	}
	for _, node := range topology.nodes {
		if node.plane != "code_traceability" {
			continue
		}
		parentFromEdge, hasParentEdge := codeParentsByChild[node.id]
		if node.kind == "repository" {
			if node.parentID != "" || hasParentEdge {
				return fmt.Errorf("requirement traceability graph repository code nodes must be parentless roots")
			}
			continue
		}
		if node.parentID == "" {
			return fmt.Errorf("requirement traceability graph non-root code node must declare parentNodeId")
		}
		parent, exists := nodesByID[node.parentID]
		if !exists {
			return fmt.Errorf("requirement traceability graph code node parent must resolve")
		}
		if parent.plane != "code_traceability" {
			return fmt.Errorf("requirement traceability graph code node parent must remain in the code traceability plane")
		}
		parentLevel, parentLevelKnown := codeAbstractionLevel(parent.kind)
		childLevel, childLevelKnown := codeAbstractionLevel(node.kind)
		if !parentLevelKnown || !childLevelKnown || parentLevel >= childLevel {
			return fmt.Errorf("requirement traceability graph code node parent abstraction level must be broader than child level")
		}
		if !hasParentEdge || parentFromEdge != node.parentID {
			return fmt.Errorf("requirement traceability graph code node parentNodeId must match exactly one parent edge")
		}
	}
	return nil
}

func validOutputTopologyRelation(edge outputTopologyEdge, from, to outputTopologyNode, nodesByID map[string]outputTopologyNode) bool {
	switch edge.plane + ":" + edge.kind {
	case "specification_coverage:contains":
		return from.plane == edge.plane && to.plane == edge.plane && from.kind != "requirement" && to.kind != "requirement"
	case "specification_coverage:declares":
		return from.plane == edge.plane && from.kind != "requirement" && to.plane == edge.plane && to.kind == "requirement"
	case "proof_coverage:proved_by_candidate":
		return from.plane == "specification_coverage" && from.kind == "requirement" && to.plane == edge.plane && to.kind == "scenario"
	case "code_traceability:contains":
		return from.plane == edge.plane && to.plane == edge.plane
	case "code_traceability:traced_to":
		return from.plane == "specification_coverage" && from.kind == "requirement" && to.plane == edge.plane
	case "native_execution_coverage:observed_by":
		codeNode, exists := nodesByID[edge.codeNodeID]
		return from.plane == "specification_coverage" && from.kind == "requirement" && to.plane == edge.plane && to.kind == "execution_evidence" && exists && codeNode.plane == "code_traceability"
	default:
		return false
	}
}

func codeAbstractionLevel(kind string) (int, bool) {
	switch kind {
	case "repository":
		return 0, true
	case "package":
		return 1, true
	case "module":
		return 2, true
	case "file":
		return 3, true
	case "symbol":
		return 4, true
	case "source_range":
		return 5, true
	default:
		return 0, false
	}
}

func outputTopologyString(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	return value, nil
}
