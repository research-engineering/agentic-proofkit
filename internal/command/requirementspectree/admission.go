package requirementspectree

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	maxSpecTreeNodes    = 4096
	maxSpecTreeEdges    = 8192
	maxSpecTreeOverlays = 4096
	maxSpecTreeDepth    = 512
)

func admitInput(raw any) (admittedInput, error) {
	value, err := treeInputShape.Admit(raw, "requirement spec tree input")
	if err != nil {
		return admittedInput{}, err
	}
	record := value.(map[string]any)
	treeID, err := admit.RuleID(record["treeId"], "requirement spec tree treeId")
	if err != nil {
		return admittedInput{}, err
	}
	rootNodeID, err := admit.RuleID(record["rootNodeId"], "requirement spec tree rootNodeId")
	if err != nil {
		return admittedInput{}, err
	}
	nodes, err := admitNodes(record["nodes"])
	if err != nil {
		return admittedInput{}, err
	}
	edges, err := admitEdges(record["edges"])
	if err != nil {
		return admittedInput{}, err
	}
	overlays, err := admitOverlays(record["overlays"])
	if err != nil {
		return admittedInput{}, err
	}
	callerAnnotations, err := admitCallerAnnotations(record["callerAnnotations"], "requirement spec tree callerAnnotations")
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		CallerAnnotations: callerAnnotations,
		Edges:             edges,
		Nodes:             nodes,
		Overlays:          overlays,
		RootNodeID:        rootNodeID,
		TreeID:            treeID,
	}, nil
}

func admitNodes(raw any) ([]node, error) {
	values := raw.([]any)
	nodes := make([]node, 0, len(values))
	for index, value := range values {
		record := value.(map[string]any)
		item, err := admitNode(record, index)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, item)
	}
	sort.SliceStable(nodes, func(left int, right int) bool {
		if nodes[left].DisplayOrder != nodes[right].DisplayOrder {
			return nodes[left].DisplayOrder < nodes[right].DisplayOrder
		}
		return nodes[left].NodeID < nodes[right].NodeID
	})
	return nodes, nil
}

func admitNode(record map[string]any, index int) (node, error) {
	context := fmt.Sprintf("requirement spec tree nodes[%d]", index)
	nodeID, err := admit.RuleID(record["nodeId"], context+" nodeId")
	if err != nil {
		return node{}, err
	}
	nodeKind := record["nodeKind"].(string)
	label, err := admit.NonEmptyText(record["label"], fmt.Sprintf("requirement spec tree node %s label", nodeID))
	if err != nil {
		return node{}, err
	}
	displayOrder, err := admit.PositiveInteger(record["displayOrder"], fmt.Sprintf("requirement spec tree node %s displayOrder", nodeID))
	if err != nil {
		return node{}, err
	}
	sourceRefs, err := admitSourceRefs(record["sourceRefs"], nodeID)
	if err != nil {
		return node{}, err
	}
	callerAnnotations, err := admitCallerAnnotations(record["callerAnnotations"], fmt.Sprintf("requirement spec tree node %s callerAnnotations", nodeID))
	if err != nil {
		return node{}, err
	}
	return node{
		CallerAnnotations: callerAnnotations,
		DisplayOrder:      displayOrder,
		Label:             label,
		NodeID:            nodeID,
		NodeKind:          nodeKind,
		SourceRefs:        sourceRefs,
	}, nil
}

func admitSourceRefs(raw any, nodeID string) ([]sourceRef, error) {
	values := raw.([]any)
	refs := make([]sourceRef, 0, len(values))
	for index, value := range values {
		record := value.(map[string]any)
		item, err := admitSourceRef(record, nodeID, index)
		if err != nil {
			return nil, err
		}
		refs = append(refs, item)
	}
	sort.SliceStable(refs, func(left int, right int) bool {
		return refs[left].SourceRefID < refs[right].SourceRefID
	})
	return refs, nil
}

func admitSourceRef(record map[string]any, nodeID string, index int) (sourceRef, error) {
	context := fmt.Sprintf("requirement spec tree node %s sourceRefs[%d]", nodeID, index)
	sourceRefID, err := admit.RuleID(record["sourceRefId"], context+" sourceRefId")
	if err != nil {
		return sourceRef{}, err
	}
	sourceRole := record["sourceRole"].(string)
	sourceRefKind := record["sourceRefKind"].(string)
	item := sourceRef{SourceRefID: sourceRefID, SourceRefKind: sourceRefKind, SourceRole: sourceRole}
	switch sourceRefKind {
	case "source_id":
		sourceID, err := admit.RuleID(record["sourceId"], fmt.Sprintf("requirement spec tree source ref %s sourceId", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		item.SourceID = sourceID
	case "path_digest":
		sourcePathText, err := admit.NonEmptyText(record["sourcePath"], fmt.Sprintf("requirement spec tree source ref %s sourcePath", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		sourcePath, err := admit.SafeRepoRelativePath(sourcePathText, fmt.Sprintf("requirement spec tree source ref %s sourcePath", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		recorded, err := digest(record["recordedSourceDigest"], fmt.Sprintf("requirement spec tree source ref %s recordedSourceDigest", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		current, err := digest(record["currentSourceDigest"], fmt.Sprintf("requirement spec tree source ref %s currentSourceDigest", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		algorithm, err := digestAlgorithm(record["digestAlgorithm"], fmt.Sprintf("requirement spec tree source ref %s digestAlgorithm", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		item.CurrentSourceDigest = current
		item.DigestAlgorithm = algorithm
		item.RecordedSourceDigest = recorded
		item.SourcePath = sourcePath
	}
	return item, nil
}

func admitEdges(raw any) ([]edge, error) {
	values := raw.([]any)
	edges := make([]edge, 0, len(values))
	for index, value := range values {
		record := value.(map[string]any)
		parent, err := admit.RuleID(record["parentNodeId"], fmt.Sprintf("requirement spec tree edges[%d] parentNodeId", index))
		if err != nil {
			return nil, err
		}
		child, err := admit.RuleID(record["childNodeId"], fmt.Sprintf("requirement spec tree edges[%d] childNodeId", index))
		if err != nil {
			return nil, err
		}
		edges = append(edges, edge{ChildNodeID: child, ParentNodeID: parent})
	}
	sort.SliceStable(edges, func(left int, right int) bool {
		if edges[left].ParentNodeID != edges[right].ParentNodeID {
			return edges[left].ParentNodeID < edges[right].ParentNodeID
		}
		return edges[left].ChildNodeID < edges[right].ChildNodeID
	})
	return edges, nil
}

func admitOverlays(raw any) ([]overlay, error) {
	values := raw.([]any)
	overlays := make([]overlay, 0, len(values))
	for index, value := range values {
		record := value.(map[string]any)
		item, err := admitOverlay(record, index)
		if err != nil {
			return nil, err
		}
		overlays = append(overlays, item)
	}
	sort.SliceStable(overlays, func(left int, right int) bool {
		return overlays[left].OverlayID < overlays[right].OverlayID
	})
	return overlays, nil
}

func admitOverlay(record map[string]any, index int) (overlay, error) {
	context := fmt.Sprintf("requirement spec tree overlays[%d]", index)
	overlayID, err := admit.RuleID(record["overlayId"], context+" overlayId")
	if err != nil {
		return overlay{}, err
	}
	overlayKind := record["overlayKind"].(string)
	targetNodeID, err := admit.RuleID(record["targetNodeId"], fmt.Sprintf("requirement spec tree overlay %s targetNodeId", overlayID))
	if err != nil {
		return overlay{}, err
	}
	refKind := record["refKind"].(string)
	refID, err := admit.RuleID(record["refId"], fmt.Sprintf("requirement spec tree overlay %s refId", overlayID))
	if err != nil {
		return overlay{}, err
	}
	label, err := admit.NonEmptyText(record["label"], fmt.Sprintf("requirement spec tree overlay %s label", overlayID))
	if err != nil {
		return overlay{}, err
	}
	callerAnnotations, err := admitCallerAnnotations(record["callerAnnotations"], fmt.Sprintf("requirement spec tree overlay %s callerAnnotations", overlayID))
	if err != nil {
		return overlay{}, err
	}
	item := overlay{
		CallerAnnotations: callerAnnotations,
		Label:             label,
		OverlayID:         overlayID,
		OverlayKind:       overlayKind,
		RefID:             refID,
		RefKind:           refKind,
		TargetNodeID:      targetNodeID,
	}
	if hasKey(record, "refPath") {
		refPathText, err := admit.NonEmptyText(record["refPath"], fmt.Sprintf("requirement spec tree overlay %s refPath", overlayID))
		if err != nil {
			return overlay{}, err
		}
		refPath, err := admit.SafeRepoRelativePath(refPathText, fmt.Sprintf("requirement spec tree overlay %s refPath", overlayID))
		if err != nil {
			return overlay{}, err
		}
		refDigest, err := digest(record["refDigest"], fmt.Sprintf("requirement spec tree overlay %s refDigest", overlayID))
		if err != nil {
			return overlay{}, err
		}
		algorithm, err := digestAlgorithm(record["digestAlgorithm"], fmt.Sprintf("requirement spec tree overlay %s digestAlgorithm", overlayID))
		if err != nil {
			return overlay{}, err
		}
		item.RefDigest = refDigest
		item.RefPath = refPath
		item.DigestAlgorithm = algorithm
		return item, nil
	}
	return item, nil
}

func admitCallerAnnotations(raw any, context string) ([]string, error) {
	values, err := admit.TextArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	return admit.SortedText(values, context, true)
}

func digest(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be a sha256 digest", context)
	}
	return value, nil
}

func digestAlgorithm(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if value != "sha256" {
		return "", fmt.Errorf("%s must be sha256", context)
	}
	return value, nil
}

func hasKey(record map[string]any, key string) bool {
	_, ok := record[key]
	return ok
}
