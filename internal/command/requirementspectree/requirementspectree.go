package requirementspectree

import (
	"encoding/json"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

type Result struct {
	ExitCode int
	Report   report.Record
	Tree     Tree
}

func Build(raw any) (report.Record, int, error) {
	result, err := Evaluate(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	return result.Report, result.ExitCode, nil
}

func Evaluate(raw any) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Result{}, err
	}
	validation := validate(input)
	record := buildRecord(input, validation)
	exitCode := 1
	if record.State == "passed" {
		exitCode = 0
	}
	return Result{ExitCode: exitCode, Report: record, Tree: input}, nil
}

func TreeValue(tree Tree) map[string]any {
	nodes := make([]any, 0, len(tree.Nodes))
	for _, node := range tree.Nodes {
		sourceRefs := make([]any, 0, len(node.SourceRefs))
		for _, ref := range node.SourceRefs {
			record := map[string]any{
				"sourceRefId":   ref.SourceRefID,
				"sourceRefKind": ref.SourceRefKind,
				"sourceRole":    ref.SourceRole,
			}
			if ref.CurrentSourceDigest != "" {
				record["currentSourceDigest"] = ref.CurrentSourceDigest
			}
			if ref.DigestAlgorithm != "" {
				record["digestAlgorithm"] = ref.DigestAlgorithm
			}
			if ref.RecordedSourceDigest != "" {
				record["recordedSourceDigest"] = ref.RecordedSourceDigest
			}
			if ref.SourceID != "" {
				record["sourceId"] = ref.SourceID
			}
			if ref.SourcePath != "" {
				record["sourcePath"] = ref.SourcePath
			}
			sourceRefs = append(sourceRefs, record)
		}
		nodes = append(nodes, map[string]any{
			"callerAnnotations": stringsToAny(node.CallerAnnotations),
			"displayOrder":      json.Number(strconv.Itoa(node.DisplayOrder)),
			"label":             node.Label,
			"nodeId":            node.NodeID,
			"nodeKind":          node.NodeKind,
			"sourceRefs":        sourceRefs,
		})
	}
	edges := make([]any, 0, len(tree.Edges))
	for _, edge := range tree.Edges {
		edges = append(edges, map[string]any{"childNodeId": edge.ChildNodeID, "parentNodeId": edge.ParentNodeID})
	}
	return map[string]any{
		"callerAnnotations": stringsToAny(tree.CallerAnnotations),
		"edges":             edges,
		"nodes":             nodes,
		"overlays":          overlaysValue(tree.Overlays),
		"rootNodeId":        tree.RootNodeID,
		"schemaVersion":     json.Number("2"),
		"treeId":            tree.TreeID,
	}
}

func overlaysValue(overlays []Overlay) []any {
	values := make([]any, 0, len(overlays))
	for _, overlay := range overlays {
		record := map[string]any{
			"callerAnnotations": stringsToAny(overlay.CallerAnnotations),
			"label":             overlay.Label,
			"overlayId":         overlay.OverlayID,
			"overlayKind":       overlay.OverlayKind,
			"refId":             overlay.RefID,
			"refKind":           overlay.RefKind,
			"targetNodeId":      overlay.TargetNodeID,
		}
		if overlay.DigestAlgorithm != "" {
			record["digestAlgorithm"] = overlay.DigestAlgorithm
		}
		if overlay.RefDigest != "" {
			record["refDigest"] = overlay.RefDigest
		}
		if overlay.RefPath != "" {
			record["refPath"] = overlay.RefPath
		}
		values = append(values, record)
	}
	return values
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
