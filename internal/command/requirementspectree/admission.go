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
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("requirement spec tree input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"callerAnnotations", "edges", "nodes", "overlays", "rootNodeId", "schemaVersion", "treeId"}, "requirement spec tree input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 2) {
		return admittedInput{}, fmt.Errorf("requirement spec tree schemaVersion must be 2")
	}
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
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement spec tree nodes must be a non-empty array")
	}
	if len(values) > maxSpecTreeNodes {
		return nil, fmt.Errorf("requirement spec tree nodes exceed the %d-node limit", maxSpecTreeNodes)
	}
	nodes := make([]node, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement spec tree nodes[%d] must be an object", index)
		}
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
	if err := admit.KnownKeys(record, []string{"callerAnnotations", "displayOrder", "label", "nodeId", "nodeKind", "sourceRefs"}, context); err != nil {
		return node{}, err
	}
	nodeID, err := admit.RuleID(record["nodeId"], context+" nodeId")
	if err != nil {
		return node{}, err
	}
	nodeKind, err := admit.Enum(record["nodeKind"], nodeKinds, fmt.Sprintf("requirement spec tree node %s nodeKind", nodeID))
	if err != nil {
		return node{}, err
	}
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
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement spec tree node %s sourceRefs must be a non-empty array", nodeID)
	}
	refs := make([]sourceRef, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement spec tree node %s sourceRefs[%d] must be an object", nodeID, index)
		}
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
	if err := admit.KnownKeys(record, []string{"currentSourceDigest", "digestAlgorithm", "recordedSourceDigest", "sourceId", "sourcePath", "sourceRefId", "sourceRefKind", "sourceRole"}, context); err != nil {
		return sourceRef{}, err
	}
	sourceRefID, err := admit.RuleID(record["sourceRefId"], context+" sourceRefId")
	if err != nil {
		return sourceRef{}, err
	}
	sourceRole, err := admit.Enum(record["sourceRole"], sourceRoles, fmt.Sprintf("requirement spec tree source ref %s sourceRole", sourceRefID))
	if err != nil {
		return sourceRef{}, err
	}
	sourceRefKind, err := admit.Enum(record["sourceRefKind"], sourceRefKinds, fmt.Sprintf("requirement spec tree source ref %s sourceRefKind", sourceRefID))
	if err != nil {
		return sourceRef{}, err
	}
	item := sourceRef{SourceRefID: sourceRefID, SourceRefKind: sourceRefKind, SourceRole: sourceRole}
	switch sourceRefKind {
	case "source_id":
		if hasAnyKey(record, "sourcePath", "recordedSourceDigest", "currentSourceDigest", "digestAlgorithm") {
			return sourceRef{}, fmt.Errorf("requirement spec tree source ref %s source_id must not include path or digest fields", sourceRefID)
		}
		sourceID, err := admit.RuleID(record["sourceId"], fmt.Sprintf("requirement spec tree source ref %s sourceId", sourceRefID))
		if err != nil {
			return sourceRef{}, err
		}
		item.SourceID = sourceID
	case "path_digest":
		if hasAnyKey(record, "sourceId") {
			return sourceRef{}, fmt.Errorf("requirement spec tree source ref %s path_digest must not include sourceId", sourceRefID)
		}
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
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement spec tree edges must be an array")
	}
	if len(values) > maxSpecTreeEdges {
		return nil, fmt.Errorf("requirement spec tree edges exceed the %d-edge limit", maxSpecTreeEdges)
	}
	edges := make([]edge, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement spec tree edges[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"childNodeId", "parentNodeId"}, fmt.Sprintf("requirement spec tree edges[%d]", index)); err != nil {
			return nil, err
		}
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
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement spec tree overlays must be an array")
	}
	if len(values) > maxSpecTreeOverlays {
		return nil, fmt.Errorf("requirement spec tree overlays exceed the %d-overlay limit", maxSpecTreeOverlays)
	}
	overlays := make([]overlay, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement spec tree overlays[%d] must be an object", index)
		}
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
	if err := admit.KnownKeys(record, []string{"callerAnnotations", "digestAlgorithm", "label", "overlayId", "overlayKind", "refDigest", "refId", "refKind", "refPath", "targetNodeId"}, context); err != nil {
		return overlay{}, err
	}
	overlayID, err := admit.RuleID(record["overlayId"], context+" overlayId")
	if err != nil {
		return overlay{}, err
	}
	overlayKind, err := admit.Enum(record["overlayKind"], overlayKinds, fmt.Sprintf("requirement spec tree overlay %s overlayKind", overlayID))
	if err != nil {
		return overlay{}, err
	}
	targetNodeID, err := admit.RuleID(record["targetNodeId"], fmt.Sprintf("requirement spec tree overlay %s targetNodeId", overlayID))
	if err != nil {
		return overlay{}, err
	}
	refKind, err := admit.Enum(record["refKind"], overlayRefKinds, fmt.Sprintf("requirement spec tree overlay %s refKind", overlayID))
	if err != nil {
		return overlay{}, err
	}
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
	if hasAnyKey(record, "refDigest", "digestAlgorithm") {
		return overlay{}, fmt.Errorf("requirement spec tree overlay %s digest fields require refPath", overlayID)
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

func hasAnyKey(record map[string]any, keys ...string) bool {
	for _, key := range keys {
		if hasKey(record, key) {
			return true
		}
	}
	return false
}

func hasKey(record map[string]any, key string) bool {
	_, ok := record[key]
	return ok
}
