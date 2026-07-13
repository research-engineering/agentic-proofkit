package requirementgraph

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maxCodeSourceBytes = 4 << 20

const (
	maxGraphNodes       = 20_000
	maxGraphEdges       = 80_000
	maxGraphOutputBytes = 24 << 20
)

type codeSource struct {
	content []byte
	digest  string
}

var nonClaims = []string{
	"Traceability graph is a derived projection and does not infer code topology, native execution coverage, proof freshness, merge, release, or rollout readiness.",
	"Specification, proof, code traceability, and native execution remain distinct evidence planes.",
}

func Build(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement traceability graph input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"codeSources", "codeTopology", "context", "graphId", "schemaVersion"}, "requirement traceability graph input"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, fmt.Errorf("requirement traceability graph schemaVersion must be 1")
	}
	graphID, err := admit.RuleID(record["graphId"], "requirement traceability graph graphId")
	if err != nil {
		return nil, err
	}
	snapshot, err := requirementcontext.AdmitSnapshot(record["context"])
	if err != nil {
		return nil, err
	}
	nodes := []map[string]any{}
	edges := []map[string]any{}
	for _, node := range snapshot.Tree.Nodes {
		nodes = append(nodes, map[string]any{"evidencePlane": "specification_coverage", "kind": node.NodeKind, "label": node.Label, "nodeId": "spec:" + node.NodeID, "sourceId": node.NodeID})
	}
	for _, edge := range snapshot.Tree.Edges {
		fromNodeID := "spec:" + edge.ParentNodeID
		toNodeID := "spec:" + edge.ChildNodeID
		edgeID, err := semanticGraphID("spec-edge", map[string]any{"edgeKind": "contains", "fromNodeId": fromNodeID, "toNodeId": toNodeID})
		if err != nil {
			return nil, err
		}
		edges = append(edges, map[string]any{"edgeId": edgeID, "edgeKind": "contains", "evidencePlane": "specification_coverage", "fromNodeId": fromNodeID, "toNodeId": toNodeID})
	}
	requirementNodeIDs, err := appendRequirementNodes(snapshot, &nodes)
	if err != nil {
		return nil, err
	}
	if err := appendSpecificationRequirementEdges(snapshot, snapshot.Tree, &edges); err != nil {
		return nil, err
	}
	if err := appendProofEdges(snapshot, requirementNodeIDs, &nodes, &edges); err != nil {
		return nil, err
	}
	codeSources, err := admitCodeSources(record["codeSources"])
	if err != nil {
		return nil, err
	}
	if record["codeTopology"] != nil {
		if err := appendCodeTopology(record["codeTopology"], codeSources, requirementNodeIDs, &nodes, &edges); err != nil {
			return nil, err
		}
	}
	if len(nodes) > maxGraphNodes || len(edges) > maxGraphEdges {
		return nil, fmt.Errorf("requirement traceability graph exceeds node or edge limit")
	}
	if err := uniqueGraphIdentities(nodes, edges); err != nil {
		return nil, err
	}
	sort.Slice(nodes, func(left, right int) bool { return nodes[left]["nodeId"].(string) < nodes[right]["nodeId"].(string) })
	sort.Slice(edges, func(left, right int) bool { return edges[left]["edgeId"].(string) < edges[right]["edgeId"].(string) })
	output := map[string]any{"edgeCount": len(edges), "edges": mapsToAny(edges), "graphId": graphID, "graphKind": "proofkit.requirement-traceability-graph", "nodeCount": len(nodes), "nodes": mapsToAny(nodes), "nonClaims": admit.StringSliceToAny(nonClaims), "schemaVersion": json.Number("1"), "snapshotId": snapshot.SnapshotID}
	encoded, err := stablejson.Marshal(output)
	if err != nil || len(encoded) > maxGraphOutputBytes {
		return nil, fmt.Errorf("requirement traceability graph exceeds output byte limit")
	}
	return output, nil
}

func appendSpecificationRequirementEdges(snapshot requirementcontext.Snapshot, tree requirementspectree.Tree, edges *[]map[string]any) error {
	requirementsBySource := map[string][]string{}
	for _, source := range snapshot.RequirementSources {
		for _, requirement := range source.Requirements {
			requirementsBySource[source.SourceID] = append(requirementsBySource[source.SourceID], requirement.RequirementID)
		}
	}
	for _, node := range tree.Nodes {
		for _, ref := range node.SourceRefs {
			if ref.SourceRole != "requirements" {
				continue
			}
			for _, requirementID := range requirementsBySource[ref.SourceID] {
				if len(*edges) >= maxGraphEdges {
					return fmt.Errorf("requirement traceability graph exceeds edge limit")
				}
				fromNodeID := "spec:" + node.NodeID
				toNodeID := "requirement:" + requirementID
				edgeID, err := semanticGraphID("declaration-edge", map[string]any{"edgeKind": "declares", "fromNodeId": fromNodeID, "toNodeId": toNodeID})
				if err != nil {
					return err
				}
				*edges = append(*edges, map[string]any{"edgeId": edgeID, "edgeKind": "declares", "evidencePlane": "specification_coverage", "fromNodeId": fromNodeID, "toNodeId": toNodeID})
			}
		}
	}
	return nil
}

func uniqueGraphIdentities(nodes, edges []map[string]any) error {
	seenNodes := map[string]struct{}{}
	for _, node := range nodes {
		id := node["nodeId"].(string)
		if _, exists := seenNodes[id]; exists {
			return fmt.Errorf("requirement traceability graph node ids must be unique")
		}
		seenNodes[id] = struct{}{}
	}
	seenEdges := map[string]struct{}{}
	for _, edge := range edges {
		id := edge["edgeId"].(string)
		if _, exists := seenEdges[id]; exists {
			return fmt.Errorf("requirement traceability graph edge ids must be unique")
		}
		seenEdges[id] = struct{}{}
		if _, ok := seenNodes[edge["fromNodeId"].(string)]; !ok {
			return fmt.Errorf("requirement traceability graph edge source must resolve")
		}
		if _, ok := seenNodes[edge["toNodeId"].(string)]; !ok {
			return fmt.Errorf("requirement traceability graph edge target must resolve")
		}
	}
	return nil
}

func appendRequirementNodes(snapshot requirementcontext.Snapshot, nodes *[]map[string]any) (map[string]struct{}, error) {
	ids := map[string]struct{}{}
	for _, source := range snapshot.RequirementSources {
		for _, requirement := range source.Requirements {
			id := requirement.RequirementID
			if _, exists := ids[id]; exists {
				return nil, fmt.Errorf("requirement traceability graph requirement ids must be unique")
			}
			ids[id] = struct{}{}
			*nodes = append(*nodes, map[string]any{"evidencePlane": "specification_coverage", "kind": "requirement", "label": id, "nodeId": "requirement:" + id, "sourceId": id})
		}
	}
	return ids, nil
}

func appendProofEdges(snapshot requirementcontext.Snapshot, requirementIDs map[string]struct{}, nodes *[]map[string]any, edges *[]map[string]any) error {
	if snapshot.ProofBinding == nil {
		return nil
	}
	seenBindings := map[string]struct{}{}
	for _, binding := range snapshot.ProofBinding.Bindings {
		requirementID := binding.RequirementID
		if _, ok := requirementIDs[requirementID]; !ok {
			continue
		}
		identity := map[string]any{"requirementId": requirementID, "scenarioId": binding.ScenarioID, "witnessId": binding.WitnessID, "witnessKind": binding.WitnessKind, "witnessPath": binding.WitnessPath}
		nodeID, err := semanticGraphID("proof", identity)
		if err != nil {
			return err
		}
		if _, duplicate := seenBindings[nodeID]; duplicate {
			return fmt.Errorf("requirement traceability graph proof bindings must be unique")
		}
		seenBindings[nodeID] = struct{}{}
		if len(*nodes) >= maxGraphNodes || len(*edges) >= maxGraphEdges {
			return fmt.Errorf("requirement traceability graph exceeds node or edge limit")
		}
		*nodes = append(*nodes, map[string]any{"evidencePlane": "proof_coverage", "kind": "scenario", "label": binding.ScenarioID, "nodeId": nodeID, "requirementId": requirementID, "scenarioId": binding.ScenarioID, "sourceId": binding.WitnessID, "witnessId": binding.WitnessID, "witnessKind": binding.WitnessKind, "witnessPath": binding.WitnessPath})
		edgeID, err := semanticGraphID("proof-edge", map[string]any{"fromNodeId": "requirement:" + requirementID, "toNodeId": nodeID})
		if err != nil {
			return err
		}
		*edges = append(*edges, map[string]any{"edgeId": edgeID, "edgeKind": "proved_by_candidate", "evidencePlane": "proof_coverage", "fromNodeId": "requirement:" + requirementID, "toNodeId": nodeID})
	}
	return nil
}

func appendCodeTopology(raw any, codeSources map[string]codeSource, requirementIDs map[string]struct{}, nodes *[]map[string]any, edges *[]map[string]any) error {
	record, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("codeTopology must be an object")
	}
	if err := admit.KnownKeys(record, []string{"edges", "nativeCoverage", "nodes", "topologyId"}, "codeTopology"); err != nil {
		return err
	}
	if _, err := admit.RuleID(record["topologyId"], "codeTopology topologyId"); err != nil {
		return err
	}
	rawNodes, ok := record["nodes"].([]any)
	if !ok {
		return fmt.Errorf("codeTopology nodes must be an array")
	}
	type admittedCodeNode struct {
		level  string
		parent string
	}
	levels := map[string]int{"repository": 0, "package": 1, "module": 2, "file": 3, "symbol": 4, "source_range": 5}
	known := map[string]admittedCodeNode{}
	for _, rawNode := range rawNodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			return fmt.Errorf("codeTopology node must be an object")
		}
		if err := admit.KnownKeys(node, []string{"abstractionLevel", "byteEnd", "byteStart", "currentnessState", "label", "nodeId", "parentNodeId", "sourceDigest", "sourcePath", "symbolId"}, "codeTopology node"); err != nil {
			return err
		}
		id, err := admit.RuleID(node["nodeId"], "codeTopology nodeId")
		if err != nil {
			return err
		}
		if _, exists := known[id]; exists {
			return fmt.Errorf("codeTopology node ids must be unique")
		}
		label, err := admit.NonEmptyText(node["label"], "codeTopology node label")
		if err != nil {
			return err
		}
		level, err := admit.Enum(node["abstractionLevel"], map[string]struct{}{"file": {}, "module": {}, "package": {}, "repository": {}, "source_range": {}, "symbol": {}}, "codeTopology node abstractionLevel")
		if err != nil {
			return err
		}
		parentID := ""
		if node["parentNodeId"] != nil {
			parentID, err = admit.RuleID(node["parentNodeId"], "codeTopology node parentNodeId")
			if err != nil {
				return err
			}
		}
		if (level == "repository") != (parentID == "") {
			return fmt.Errorf("codeTopology repository nodes must be roots and every other node must declare parentNodeId")
		}
		pathText, err := admit.NonEmptyText(node["sourcePath"], "codeTopology node sourcePath")
		if err != nil {
			return err
		}
		path, err := admit.SafeRepoRelativePath(pathText, "codeTopology node sourcePath")
		if err != nil {
			return err
		}
		digestRef, err := digestRef(node["sourceDigest"], "codeTopology node sourceDigest")
		if err != nil {
			return err
		}
		currentness, err := admit.Enum(node["currentnessState"], map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}, "codeTopology node currentnessState")
		if err != nil {
			return err
		}
		projected := map[string]any{"currentnessState": currentness, "evidencePlane": "code_traceability", "kind": level, "label": label, "nodeId": "code:" + id, "sourceDigest": digestRef, "sourceId": path}
		if parentID != "" {
			projected["parentNodeId"] = "code:" + parentID
		}
		if node["symbolId"] != nil {
			symbolID, err := admit.RuleID(node["symbolId"], "codeTopology node symbolId")
			if err != nil {
				return err
			}
			projected["symbolId"] = symbolID
		}
		hasRange := node["byteStart"] != nil || node["byteEnd"] != nil
		if (level == "source_range") != hasRange {
			return fmt.Errorf("codeTopology source_range nodes require byteStart and byteEnd, and other levels must not declare them")
		}
		if hasRange {
			start, err := nonNegativeInteger(node["byteStart"], "codeTopology node byteStart")
			if err != nil {
				return err
			}
			end, err := nonNegativeInteger(node["byteEnd"], "codeTopology node byteEnd")
			if err != nil || end <= start {
				return fmt.Errorf("codeTopology node byte range must be non-empty and half-open")
			}
			projected["byteEnd"] = end
			projected["byteStart"] = start
			projected["coordinateUnit"] = "utf8_byte"
			projected["sourceDigest"] = digestRef
			projected["rangeVerification"] = "unverified"
			if source, exists := codeSources[path]; exists {
				if source.digest != digestRef {
					return fmt.Errorf("codeTopology node sourceDigest does not match codeSources content")
				}
				if end > len(source.content) || !utf8Boundary(source.content, start) || !utf8Boundary(source.content, end) {
					return fmt.Errorf("codeTopology node byte range must resolve to UTF-8 boundaries in codeSources content")
				}
				projected["rangeVerification"] = "verified"
			}
		}
		known[id] = admittedCodeNode{level: level, parent: parentID}
		*nodes = append(*nodes, projected)
	}
	for id, node := range known {
		if node.parent == "" {
			continue
		}
		parent, exists := known[node.parent]
		if !exists {
			return fmt.Errorf("codeTopology node references unknown parent")
		}
		if levels[parent.level] >= levels[node.level] {
			return fmt.Errorf("codeTopology parent abstraction level must be broader than child level")
		}
		fromNodeID := "code:" + node.parent
		toNodeID := "code:" + id
		edgeID, err := semanticGraphID("code-parent-edge", map[string]any{"edgeKind": "contains", "fromNodeId": fromNodeID, "toNodeId": toNodeID})
		if err != nil {
			return err
		}
		*edges = append(*edges, map[string]any{"edgeId": edgeID, "edgeKind": "contains", "evidencePlane": "code_traceability", "fromNodeId": fromNodeID, "toNodeId": toNodeID})
	}
	rawEdges, ok := record["edges"].([]any)
	if !ok {
		return fmt.Errorf("codeTopology edges must be an array")
	}
	seenRelations := map[string]struct{}{}
	for _, rawEdge := range rawEdges {
		edge, ok := rawEdge.(map[string]any)
		if !ok {
			return fmt.Errorf("codeTopology edge must be an object")
		}
		if err := admit.KnownKeys(edge, []string{"authorityClass", "codeNodeId", "currentnessState", "evidenceRefs", "requirementId"}, "codeTopology edge"); err != nil {
			return err
		}
		codeID, err := admit.RuleID(edge["codeNodeId"], "codeTopology edge codeNodeId")
		if err != nil {
			return err
		}
		requirementID, err := admit.RuleID(edge["requirementId"], "codeTopology edge requirementId")
		if err != nil {
			return err
		}
		if _, ok := known[codeID]; !ok {
			return fmt.Errorf("codeTopology edge references unknown code node")
		}
		if _, ok := requirementIDs[requirementID]; !ok {
			return fmt.Errorf("codeTopology edge references unknown requirement")
		}
		evidenceRefs, err := admittedRuleIDArray(edge["evidenceRefs"], "codeTopology edge evidenceRefs")
		if err != nil || len(evidenceRefs) == 0 {
			return fmt.Errorf("codeTopology edge evidenceRefs must be a non-empty unique array")
		}
		authority, err := admit.Enum(edge["authorityClass"], map[string]struct{}{"caller_reported": {}, "owner_admitted": {}}, "codeTopology edge authorityClass")
		if err != nil {
			return err
		}
		currentness, err := admit.Enum(edge["currentnessState"], map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}, "codeTopology edge currentnessState")
		if err != nil {
			return err
		}
		relation := map[string]any{"authorityClass": authority, "codeNodeId": codeID, "currentnessState": currentness, "evidenceRefs": admit.StringSliceToAny(evidenceRefs), "requirementId": requirementID}
		edgeID, err := semanticGraphID("code-edge", relation)
		if err != nil {
			return err
		}
		if _, duplicate := seenRelations[edgeID]; duplicate {
			return fmt.Errorf("codeTopology traceability relations must be unique")
		}
		seenRelations[edgeID] = struct{}{}
		if len(*edges) >= maxGraphEdges {
			return fmt.Errorf("requirement traceability graph exceeds edge limit")
		}
		*edges = append(*edges, map[string]any{"authorityClass": authority, "currentnessState": currentness, "edgeId": edgeID, "edgeKind": "traced_to", "evidencePlane": "code_traceability", "evidenceRefs": admit.StringSliceToAny(evidenceRefs), "fromNodeId": "requirement:" + requirementID, "toNodeId": "code:" + codeID})
	}
	if rawCoverage := record["nativeCoverage"]; rawCoverage != nil {
		coverage, ok := rawCoverage.([]any)
		if !ok {
			return fmt.Errorf("codeTopology nativeCoverage must be an array")
		}
		seenEvidence := map[string]map[string]any{}
		seenObservations := map[string]struct{}{}
		for _, raw := range coverage {
			item, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("codeTopology native coverage must be an object")
			}
			if err := admit.KnownKeys(item, []string{"authorityClass", "codeNodeId", "currentnessState", "evidenceRef", "producerId", "requirementId", "state"}, "codeTopology native coverage"); err != nil {
				return err
			}
			codeID, err := admit.RuleID(item["codeNodeId"], "codeTopology native coverage codeNodeId")
			if err != nil {
				return err
			}
			if _, ok := known[codeID]; !ok {
				return fmt.Errorf("codeTopology native coverage references unknown code node")
			}
			requirementID, err := admit.RuleID(item["requirementId"], "codeTopology native coverage requirementId")
			if err != nil {
				return err
			}
			if _, ok := requirementIDs[requirementID]; !ok {
				return fmt.Errorf("codeTopology native coverage references unknown requirement")
			}
			evidenceRef, err := admit.RuleID(item["evidenceRef"], "codeTopology native coverage evidenceRef")
			if err != nil {
				return err
			}
			state, err := admit.Enum(item["state"], map[string]struct{}{"failed": {}, "passed": {}, "skipped": {}, "unavailable": {}}, "codeTopology native coverage state")
			if err != nil {
				return err
			}
			authority, err := admit.Enum(item["authorityClass"], map[string]struct{}{"caller_reported": {}, "receipt_admitted": {}}, "codeTopology native coverage authorityClass")
			if err != nil {
				return err
			}
			currentness, err := admit.Enum(item["currentnessState"], map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}, "codeTopology native coverage currentnessState")
			if err != nil {
				return err
			}
			producerID, err := admit.RuleID(item["producerId"], "codeTopology native coverage producerId")
			if err != nil {
				return err
			}
			nodeID := "execution:" + evidenceRef
			evidenceNode := map[string]any{"authorityClass": authority, "currentnessState": currentness, "evidencePlane": "native_execution_coverage", "kind": "execution_evidence", "label": evidenceRef, "nodeId": nodeID, "producerId": producerID, "sourceId": evidenceRef, "state": state}
			if previous, exists := seenEvidence[evidenceRef]; exists {
				if !reflect.DeepEqual(previous, evidenceNode) {
					return fmt.Errorf("codeTopology native coverage evidence identity has conflicting facts")
				}
			} else {
				*nodes = append(*nodes, evidenceNode)
				seenEvidence[evidenceRef] = evidenceNode
			}
			edgeID, err := semanticGraphID("execution-edge", map[string]any{"codeNodeId": codeID, "evidenceRef": evidenceRef, "requirementId": requirementID})
			if err != nil {
				return err
			}
			if _, duplicate := seenObservations[edgeID]; duplicate {
				return fmt.Errorf("codeTopology native coverage observations must be unique")
			}
			seenObservations[edgeID] = struct{}{}
			if len(*nodes) > maxGraphNodes || len(*edges) >= maxGraphEdges {
				return fmt.Errorf("requirement traceability graph exceeds node or edge limit")
			}
			*edges = append(*edges, map[string]any{"codeNodeId": "code:" + codeID, "edgeId": edgeID, "edgeKind": "observed_by", "evidencePlane": "native_execution_coverage", "fromNodeId": "requirement:" + requirementID, "toNodeId": nodeID})
		}
	}
	return nil
}

func semanticGraphID(prefix string, identity map[string]any) (string, error) {
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		return "", err
	}
	return prefix + ":" + strings.TrimPrefix(digest.SHA256TextRef(string(encoded)), "sha256:"), nil
}

func admitCodeSources(raw any) (map[string]codeSource, error) {
	if raw == nil {
		return map[string]codeSource{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement traceability graph codeSources must be an array")
	}
	result := make(map[string]codeSource, len(values))
	totalBytes := 0
	for index, rawValue := range values {
		record, ok := rawValue.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement traceability graph codeSources[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"content", "path"}, "requirement traceability graph code source"); err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], "requirement traceability graph code source path")
		if err != nil {
			return nil, err
		}
		path, err := admit.SafeRepoRelativePath(pathText, "requirement traceability graph code source path")
		if err != nil {
			return nil, err
		}
		if _, exists := result[path]; exists {
			return nil, fmt.Errorf("requirement traceability graph code source paths must be unique")
		}
		content, ok := record["content"].(string)
		if !ok || !utf8.ValidString(content) {
			return nil, fmt.Errorf("requirement traceability graph code source content must be UTF-8 text")
		}
		if admit.ContainsSecretLikeValue(content) {
			return nil, fmt.Errorf("requirement traceability graph code source content must not contain secret-like values")
		}
		totalBytes += len(content)
		if totalBytes > maxCodeSourceBytes {
			return nil, fmt.Errorf("requirement traceability graph code sources exceed byte limit")
		}
		result[path] = codeSource{content: []byte(content), digest: digest.SHA256TextRef(content)}
	}
	return result, nil
}

func utf8Boundary(content []byte, offset int) bool {
	return offset == 0 || offset == len(content) || (offset > 0 && offset < len(content) && utf8.RuneStart(content[offset]))
}

func admittedRuleIDArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, rawValue := range values {
		value, err := admit.RuleID(rawValue, context)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func nonNegativeInteger(raw any, context string) (int, error) {
	if value, ok := raw.(int); ok {
		if value < 0 {
			return 0, fmt.Errorf("%s must be a non-negative integer", context)
		}
		return value, nil
	}
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	value, err := strconv.Atoi(number.String())
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	return value, nil
}
func digestRef(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil || !strings.HasPrefix(value, "sha256:") {
		return "", fmt.Errorf("%s must be a sha256 digest reference", context)
	}
	if _, err := admit.LowercaseSHA256(strings.TrimPrefix(value, "sha256:"), context); err != nil {
		return "", err
	}
	return value, nil
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
