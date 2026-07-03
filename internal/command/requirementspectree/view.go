package requirementspectree

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

var viewNonClaims = []string{
	"Requirement spec tree views are presentation-only derived products.",
	"Requirement spec tree views do not compute source digest freshness from repository files.",
	"Requirement spec tree views do not execute native witnesses.",
	"Requirement spec tree views do not make rendered output authoritative.",
	"Requirement spec tree views do not prove coverage completeness, merge approval, release approval, rollout approval, or production readiness.",
}

func BuildViewJSON(raw any) (any, int, error) {
	view, err := buildView(raw)
	if err != nil {
		return nil, 1, err
	}
	return view, 0, nil
}

func BuildViewMarkdown(raw any) (string, int, error) {
	view, err := buildView(raw)
	if err != nil {
		return "", 1, err
	}
	return markdown(view) + "\n", 0, nil
}

func BuildViewHTML(raw any) (string, int, error) {
	view, err := buildView(raw)
	if err != nil {
		return "", 1, err
	}
	markdownOutput := markdown(view) + "\n"
	baseHTML := html(view, nil)
	exports := []browserdoc.ExportFile{
		browserdoc.Export("Download Markdown", stringValue(view["treeId"])+".md", markdownOutput),
		browserdoc.Export("Download HTML", stringValue(view["treeId"])+".html", baseHTML),
	}
	return html(view, exports), 0, nil
}

func buildView(raw any) (map[string]any, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, err
	}
	validation := validate(input)
	if len(validation.Failures) > 0 {
		return nil, fmt.Errorf("cannot build requirement spec tree view from failed requirement spec tree: %s", strings.Join(validation.Failures, ", "))
	}
	projection := treeProjection(input)
	nonClaims := append([]string{}, viewNonClaims...)
	nonClaims = append(nonClaims, boundaryNonClaims...)
	nonClaims = append(nonClaims, input.CallerNonClaims...)
	return map[string]any{
		"authority":                  "presentation_only",
		"edgeCount":                  len(input.Edges),
		"maxDepth":                   validation.MaxDepth,
		"nodeCount":                  len(input.Nodes),
		"nodes":                      projection.Nodes,
		"nonClaims":                  admit.StringSliceToAny(sortedUnique(nonClaims)),
		"overlayCount":               len(input.Overlays),
		"rootNodeId":                 input.RootNodeID,
		"schemaVersion":              1,
		"sourceRefCount":             len(validation.SourceRefIDs),
		"staleSourceRefCount":        len(validation.StaleSourceRefIDs),
		"state":                      "passed",
		"treeId":                     input.TreeID,
		"viewKind":                   "proofkit.requirement-spec-tree-view",
		"visibleCallerNonClaims":     admit.StringSliceToAny(allCallerNonClaims(input)),
		"visibleCallerNonClaimCount": len(allCallerNonClaims(input)),
	}, nil
}

type projectedTree struct {
	Nodes []any
}

func treeProjection(input admittedInput) projectedTree {
	nodeByID := map[string]node{}
	for _, item := range input.Nodes {
		nodeByID[item.NodeID] = item
	}
	childrenByParent := map[string][]string{}
	parentByChild := map[string]string{}
	for _, item := range input.Edges {
		childrenByParent[item.ParentNodeID] = append(childrenByParent[item.ParentNodeID], item.ChildNodeID)
		parentByChild[item.ChildNodeID] = item.ParentNodeID
	}
	for parentID := range childrenByParent {
		sort.SliceStable(childrenByParent[parentID], func(left, right int) bool {
			leftNode := nodeByID[childrenByParent[parentID][left]]
			rightNode := nodeByID[childrenByParent[parentID][right]]
			if leftNode.DisplayOrder != rightNode.DisplayOrder {
				return leftNode.DisplayOrder < rightNode.DisplayOrder
			}
			return leftNode.NodeID < rightNode.NodeID
		})
	}
	overlaysByNode := map[string][]overlay{}
	for _, item := range input.Overlays {
		overlaysByNode[item.TargetNodeID] = append(overlaysByNode[item.TargetNodeID], item)
	}
	depthByID := map[string]int{}
	assignDepth(input.RootNodeID, 1, childrenByParent, depthByID)
	orderedIDs := preorder(input.RootNodeID, childrenByParent)
	nodes := make([]any, 0, len(orderedIDs))
	for _, nodeID := range orderedIDs {
		item := nodeByID[nodeID]
		nodes = append(nodes, map[string]any{
			"callerNonClaims": admit.StringSliceToAny(item.CallerNonClaims),
			"childNodeIds":    admit.StringSliceToAny(childrenByParent[item.NodeID]),
			"depth":           depthByID[item.NodeID],
			"displayOrder":    item.DisplayOrder,
			"label":           item.Label,
			"nodeId":          item.NodeID,
			"nodeKind":        item.NodeKind,
			"overlays":        overlayViews(overlaysByNode[item.NodeID]),
			"parentNodeId":    parentByChild[item.NodeID],
			"sourceRefs":      sourceRefViews(item.SourceRefs),
		})
	}
	return projectedTree{Nodes: nodes}
}

func assignDepth(nodeID string, depth int, childrenByParent map[string][]string, depthByID map[string]int) {
	depthByID[nodeID] = depth
	for _, childID := range childrenByParent[nodeID] {
		assignDepth(childID, depth+1, childrenByParent, depthByID)
	}
}

func preorder(rootID string, childrenByParent map[string][]string) []string {
	result := []string{rootID}
	for _, childID := range childrenByParent[rootID] {
		result = append(result, preorder(childID, childrenByParent)...)
	}
	return result
}

func sourceRefViews(refs []sourceRef) []any {
	values := make([]any, 0, len(refs))
	for _, item := range refs {
		value := map[string]any{
			"sourceRefId":   item.SourceRefID,
			"sourceRefKind": item.SourceRefKind,
			"sourceRole":    item.SourceRole,
		}
		if item.SourceRefKind == "source_id" {
			value["sourceId"] = item.SourceID
		} else {
			value["currentSourceDigest"] = item.CurrentSourceDigest
			value["digestAlgorithm"] = item.DigestAlgorithm
			value["recordedSourceDigest"] = item.RecordedSourceDigest
			value["sourcePath"] = item.SourcePath
			value["staleDigest"] = item.RecordedSourceDigest != item.CurrentSourceDigest
		}
		values = append(values, value)
	}
	return values
}

func overlayViews(overlays []overlay) []any {
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

func markdown(view map[string]any) string {
	lines := []string{
		"# Requirement Spec Tree View: " + markdownfmt.Text(stringValue(view["treeId"])),
		"",
		"Authority: " + markdownfmt.Text(stringValue(view["authority"])),
		"State: " + markdownfmt.Text(stringValue(view["state"])),
		fmt.Sprintf("Nodes: %d", intValue(view["nodeCount"])),
		fmt.Sprintf("Edges: %d", intValue(view["edgeCount"])),
		fmt.Sprintf("Overlays: %d", intValue(view["overlayCount"])),
		fmt.Sprintf("Max depth: %d", intValue(view["maxDepth"])),
		"",
		"## Specification Tree",
		"",
	}
	for _, raw := range anyArray(view["nodes"]) {
		node := raw.(map[string]any)
		depth := intValue(node["depth"])
		prefix := strings.Repeat("  ", depth-1) + "- "
		lines = append(lines,
			prefix+markdownfmt.CodeSpan(stringValue(node["nodeId"]))+" "+markdownfmt.Text(stringValue(node["label"]))+" ("+markdownfmt.Text(stringValue(node["nodeKind"]))+")",
			prefix+"  Source refs: "+markdownfmt.CodeListOrNone(sourceRefIDs(anyArray(node["sourceRefs"]))),
			prefix+"  Overlays: "+markdownfmt.CodeListOrNone(overlayIDs(anyArray(node["overlays"]))),
		)
	}
	lines = append(lines, "", "## View Non-Claims", "")
	for _, claim := range stringArray(view["nonClaims"]) {
		lines = append(lines, "- "+markdownfmt.Text(claim))
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func html(view map[string]any, exports []browserdoc.ExportFile) string {
	nodes := anyArray(view["nodes"])
	cards := make([]browserdoc.Card, 0, len(nodes))
	rows := make([]browserdoc.Row, 0, len(nodes))
	kinds := []string{}
	sourceRoles := []string{}
	sourceKinds := []string{}
	overlayKinds := []string{}
	for _, raw := range nodes {
		node := raw.(map[string]any)
		nodeKind := stringValue(node["nodeKind"])
		kinds = append(kinds, nodeKind)
		roles := sourceRolesForNode(node)
		sourceRoles = append(sourceRoles, roles...)
		sourceRefKinds := sourceKindsForNode(node)
		sourceKinds = append(sourceKinds, sourceRefKinds...)
		nodeOverlayKinds := overlayKindsForNode(node)
		overlayKinds = append(overlayKinds, nodeOverlayKinds...)
		filters := []browserdoc.FilterValue{{Key: "node-kind", Value: nodeKind}}
		if len(roles) > 0 {
			filters = append(filters, browserdoc.FilterValue{Key: "source-role", Value: roles[0]})
		}
		if len(sourceRefKinds) > 0 {
			filters = append(filters, browserdoc.FilterValue{Key: "source-kind", Value: sourceRefKinds[0]})
		}
		if len(nodeOverlayKinds) > 0 {
			filters = append(filters, browserdoc.FilterValue{Key: "overlay-kind", Value: nodeOverlayKinds[0]})
		}
		search := browserdoc.SearchText(append([]string{
			stringValue(node["nodeId"]),
			stringValue(node["label"]),
			nodeKind,
			stringValue(node["parentNodeId"]),
		}, append(sourceRefIDs(anyArray(node["sourceRefs"])), overlayIDs(anyArray(node["overlays"]))...)...))
		cards = append(cards, browserdoc.Card{
			ID:           stringValue(node["nodeId"]),
			Title:        stringValue(node["label"]),
			GroupID:      "kind:" + nodeKind,
			GroupLabel:   "Kind: " + nodeKind,
			Body:         nodeBody(node),
			SearchText:   search,
			FilterValues: filters,
		})
		rows = append(rows, browserdoc.Row{
			ID: stringValue(node["nodeId"]),
			Cells: []browserdoc.Cell{
				browserdoc.TableCell("node", stringValue(node["nodeId"]), true),
				browserdoc.TableCell("label", stringValue(node["label"]), false),
				browserdoc.TableCell("kind", nodeKind, false),
				browserdoc.TableCell("depth", fmt.Sprint(intValue(node["depth"])), false),
				{Key: "sourceRefs", Value: browserdoc.ListOrNone(sourceRefIDs(anyArray(node["sourceRefs"])), true)},
				{Key: "overlays", Value: browserdoc.ListOrNone(overlayIDs(anyArray(node["overlays"])), true)},
			},
			SearchText:   search,
			FilterValues: filters,
		})
	}
	return browserdoc.HTML(browserdoc.Document{
		Title:     "Requirement Spec Tree View: " + stringValue(view["treeId"]),
		Authority: stringValue(view["authority"]),
		SummaryItems: []browserdoc.SummaryItem{
			browserdoc.Summary("State", stringValue(view["state"]), false),
			browserdoc.Summary("Root node", stringValue(view["rootNodeId"]), true),
			browserdoc.Summary("Nodes", fmt.Sprint(intValue(view["nodeCount"])), false),
			browserdoc.Summary("Edges", fmt.Sprint(intValue(view["edgeCount"])), false),
			browserdoc.Summary("Overlays", fmt.Sprint(intValue(view["overlayCount"])), false),
			browserdoc.Summary("Max depth", fmt.Sprint(intValue(view["maxDepth"])), false),
		},
		HierarchySections: []browserdoc.HierarchySection{
			{Title: "Specification tree", Items: treeHierarchy(nodes)},
			{Title: "Node kinds", Items: countHierarchy(nodes, "nodeKind", "kind:")},
		},
		Filters: []browserdoc.Filter{
			browserdoc.NewFilter("node-kind", "Node kind", kinds),
			browserdoc.NewFilter("source-role", "Source role", sourceRoles),
			browserdoc.NewFilter("source-kind", "Source kind", sourceKinds),
			browserdoc.NewFilter("overlay-kind", "Overlay kind", overlayKinds),
		},
		Cards: cards,
		Table: &browserdoc.Table{Columns: []browserdoc.Column{
			{Key: "node", Label: "Node"},
			{Key: "label", Label: "Label"},
			{Key: "kind", Label: "Kind"},
			{Key: "depth", Label: "Depth"},
			{Key: "sourceRefs", Label: "Source refs"},
			{Key: "overlays", Label: "Overlays"},
		}, Rows: rows},
		ExportFiles: exports,
		NonClaims:   stringArray(view["nonClaims"]),
	})
}

func nodeBody(node map[string]any) browserdoc.Fragment {
	return browserdoc.Concat(
		browserdoc.DefinitionList(
			browserdoc.Definition("Kind", browserdoc.Text(stringValue(node["nodeKind"]))),
			browserdoc.Definition("Parent", browserdoc.Code(stringValue(node["parentNodeId"]))),
			browserdoc.Definition("Children", browserdoc.ListOrNone(stringArray(node["childNodeIds"]), true)),
			browserdoc.Definition("Source refs", browserdoc.ListOrNone(sourceRefIDs(anyArray(node["sourceRefs"])), true)),
			browserdoc.Definition("Overlays", browserdoc.ListOrNone(overlayIDs(anyArray(node["overlays"])), true)),
		),
		browserdoc.Details("Source refs, overlays, and caller non-claims",
			browserdoc.Heading(3, "Source refs"),
			sourceRefsHTML(anyArray(node["sourceRefs"])),
			browserdoc.Heading(3, "Overlays"),
			overlaysHTML(anyArray(node["overlays"])),
			browserdoc.Heading(3, "Caller non-claims"),
			browserdoc.ListOrNone(stringArray(node["callerNonClaims"]), false),
		),
	)
}

func sourceRefsHTML(refs []any) browserdoc.Fragment {
	if len(refs) == 0 {
		return browserdoc.Text("none")
	}
	parts := make([]browserdoc.Fragment, 0, len(refs))
	for _, raw := range refs {
		ref := raw.(map[string]any)
		items := []browserdoc.DefinitionItem{
			browserdoc.Definition("Role", browserdoc.Text(stringValue(ref["sourceRole"]))),
			browserdoc.Definition("Kind", browserdoc.Text(stringValue(ref["sourceRefKind"]))),
		}
		if stringValue(ref["sourceRefKind"]) == "source_id" {
			items = append(items, browserdoc.Definition("Source id", browserdoc.Code(stringValue(ref["sourceId"]))))
		} else {
			items = append(items,
				browserdoc.Definition("Source path", browserdoc.Code(stringValue(ref["sourcePath"]))),
				browserdoc.Definition("Digest algorithm", browserdoc.Text(stringValue(ref["digestAlgorithm"]))),
				browserdoc.Definition("Recorded digest", browserdoc.Code(stringValue(ref["recordedSourceDigest"]))),
				browserdoc.Definition("Current digest", browserdoc.Code(stringValue(ref["currentSourceDigest"]))),
				browserdoc.Definition("Caller digest differs", browserdoc.Text(fmt.Sprint(ref["staleDigest"]))),
			)
		}
		parts = append(parts, browserdoc.Section(stringValue(ref["sourceRefId"]), browserdoc.DefinitionList(items...)))
	}
	return browserdoc.Concat(parts...)
}

func overlaysHTML(overlays []any) browserdoc.Fragment {
	if len(overlays) == 0 {
		return browserdoc.Text("none")
	}
	parts := make([]browserdoc.Fragment, 0, len(overlays))
	for _, raw := range overlays {
		overlay := raw.(map[string]any)
		items := []browserdoc.DefinitionItem{
			browserdoc.Definition("Label", browserdoc.Text(stringValue(overlay["label"]))),
			browserdoc.Definition("Kind", browserdoc.Text(stringValue(overlay["overlayKind"]))),
			browserdoc.Definition("Ref kind", browserdoc.Text(stringValue(overlay["refKind"]))),
			browserdoc.Definition("Ref id", browserdoc.Code(stringValue(overlay["refId"]))),
		}
		if stringValue(overlay["refPath"]) != "" {
			items = append(items,
				browserdoc.Definition("Ref path", browserdoc.Code(stringValue(overlay["refPath"]))),
				browserdoc.Definition("Ref digest", browserdoc.Code(stringValue(overlay["refDigest"]))),
				browserdoc.Definition("Digest algorithm", browserdoc.Text(stringValue(overlay["digestAlgorithm"]))),
			)
		}
		items = append(items, browserdoc.Definition("Caller non-claims", browserdoc.ListOrNone(stringArray(overlay["callerNonClaims"]), false)))
		parts = append(parts, browserdoc.Section(stringValue(overlay["overlayId"]), browserdoc.DefinitionList(items...)))
	}
	return browserdoc.Concat(parts...)
}

func sourceRolesForNode(node map[string]any) []string {
	values := []string{}
	for _, raw := range anyArray(node["sourceRefs"]) {
		values = append(values, stringValue(raw.(map[string]any)["sourceRole"]))
	}
	return sortedUnique(values)
}

func sourceKindsForNode(node map[string]any) []string {
	values := []string{}
	for _, raw := range anyArray(node["sourceRefs"]) {
		values = append(values, stringValue(raw.(map[string]any)["sourceRefKind"]))
	}
	return sortedUnique(values)
}

func overlayKindsForNode(node map[string]any) []string {
	values := []string{}
	for _, raw := range anyArray(node["overlays"]) {
		values = append(values, stringValue(raw.(map[string]any)["overlayKind"]))
	}
	return sortedUnique(values)
}

func sourceRefIDs(refs []any) []string {
	values := make([]string, 0, len(refs))
	for _, raw := range refs {
		values = append(values, stringValue(raw.(map[string]any)["sourceRefId"]))
	}
	return values
}

func overlayIDs(overlays []any) []string {
	values := make([]string, 0, len(overlays))
	for _, raw := range overlays {
		values = append(values, stringValue(raw.(map[string]any)["overlayId"]))
	}
	return values
}

func treeHierarchy(nodes []any) []browserdoc.HierarchyItem {
	items := make([]browserdoc.HierarchyItem, 0, len(nodes))
	for _, raw := range nodes {
		node := raw.(map[string]any)
		depth := intValue(node["depth"])
		items = append(items, browserdoc.HierarchyItem{
			Label:  strings.Repeat("  ", depth-1) + stringValue(node["label"]),
			Detail: stringValue(node["nodeKind"]),
			Href:   "#" + browserdoc.FragmentID("kind:"+stringValue(node["nodeKind"])),
		})
	}
	return items
}

func countHierarchy(nodes []any, key string, anchorPrefix string) []browserdoc.HierarchyItem {
	counts := map[string]int{}
	for _, raw := range nodes {
		counts[stringValue(raw.(map[string]any)[key])]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]browserdoc.HierarchyItem, 0, len(keys))
	for _, key := range keys {
		items = append(items, browserdoc.HierarchyItem{
			Label:  key,
			Detail: fmt.Sprintf("%d node(s)", counts[key]),
			Href:   "#" + browserdoc.FragmentID(anchorPrefix+key),
		})
	}
	return items
}

func allCallerNonClaims(input admittedInput) []string {
	values := append([]string{}, input.CallerNonClaims...)
	for _, item := range input.Nodes {
		values = append(values, item.CallerNonClaims...)
	}
	for _, item := range input.Overlays {
		values = append(values, item.CallerNonClaims...)
	}
	return sortedUnique(values)
}

func sortedUnique(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return uniqueSorted(result)
}

func anyArray(raw any) []any {
	if values, ok := raw.([]any); ok {
		return values
	}
	return []any{}
}

func stringArray(raw any) []string {
	return admit.AnySliceToString(anyArray(raw))
}

func stringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func intValue(raw any) int {
	value, _ := raw.(int)
	return value
}
