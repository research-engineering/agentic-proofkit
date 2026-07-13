package requirementgraph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var derivedGraphIDPattern = regexp.MustCompile(`^(proof|proof-edge|spec-edge|declaration-edge|code-parent-edge|code-edge|execution-edge):[a-f0-9]{64}$`)

func AdmitOutput(raw any, snapshotID string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement traceability graph output must be an object")
	}
	if err := admit.KnownKeys(record, []string{"edgeCount", "edges", "graphId", "graphKind", "nodeCount", "nodes", "nonClaims", "schemaVersion", "snapshotId"}, "requirement traceability graph output"); err != nil {
		return nil, err
	}
	if (!admit.JSONNumberEquals(record["schemaVersion"], 1) && record["schemaVersion"] != 1) || record["graphKind"] != "proofkit.requirement-traceability-graph" || record["snapshotId"] != snapshotID {
		return nil, fmt.Errorf("requirement traceability graph output identity is invalid")
	}
	if _, err := admit.RuleID(record["graphId"], "requirement traceability graph graphId"); err != nil {
		return nil, err
	}
	rawNodes, ok := record["nodes"].([]any)
	if !ok {
		return nil, fmt.Errorf("requirement traceability graph nodes must be an array")
	}
	rawEdges, ok := record["edges"].([]any)
	if !ok {
		return nil, fmt.Errorf("requirement traceability graph edges must be an array")
	}
	if !graphCountEquals(record["nodeCount"], len(rawNodes)) || !graphCountEquals(record["edgeCount"], len(rawEdges)) {
		return nil, fmt.Errorf("requirement traceability graph counts must match records")
	}
	nodes := make([]map[string]any, 0, len(rawNodes))
	nodesByID := map[string]map[string]any{}
	for index, rawNode := range rawNodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement traceability graph nodes[%d] must be an object", index)
		}
		if err := admitGraphNode(node); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
		nodesByID[node["nodeId"].(string)] = node
	}
	edges := make([]map[string]any, 0, len(rawEdges))
	for index, rawEdge := range rawEdges {
		edge, ok := rawEdge.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement traceability graph edges[%d] must be an object", index)
		}
		if err := admitGraphEdge(edge); err != nil {
			return nil, err
		}
		if err := admitGraphRelation(edge, nodesByID); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	if err := uniqueGraphIdentities(nodes, edges); err != nil {
		return nil, err
	}
	findings, err := secretjson.Scan(record, "traceability_graph")
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		return nil, fmt.Errorf("requirement traceability graph output contains secret-shaped data")
	}
	if err := exactGraphNonClaims(record["nonClaims"]); err != nil {
		return nil, err
	}
	if !sort.SliceIsSorted(nodes, func(left, right int) bool { return nodes[left]["nodeId"].(string) < nodes[right]["nodeId"].(string) }) || !sort.SliceIsSorted(edges, func(left, right int) bool { return edges[left]["edgeId"].(string) < edges[right]["edgeId"].(string) }) {
		return nil, fmt.Errorf("requirement traceability graph records must be canonically sorted")
	}
	encoded, err := stablejson.Marshal(record)
	if err != nil {
		return nil, err
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, err
	}
	return decoded.(map[string]any), nil
}

func admitGraphNode(node map[string]any) error {
	plane, err := admit.Enum(node["evidencePlane"], map[string]struct{}{"code_traceability": {}, "native_execution_coverage": {}, "proof_coverage": {}, "specification_coverage": {}}, "requirement traceability graph node evidencePlane")
	if err != nil {
		return err
	}
	keys := []string{"evidencePlane", "kind", "label", "nodeId", "sourceId"}
	if plane == "code_traceability" {
		keys = append(keys, "byteEnd", "byteStart", "coordinateUnit", "currentnessState", "parentNodeId", "rangeVerification", "sourceDigest", "symbolId")
	}
	if plane == "native_execution_coverage" {
		keys = append(keys, "authorityClass", "currentnessState", "producerId", "state")
	}
	if plane == "proof_coverage" {
		keys = append(keys, "requirementId", "scenarioId", "witnessId", "witnessKind", "witnessPath")
	}
	if plane == "specification_coverage" {
		if _, err := admit.Enum(node["kind"], map[string]struct{}{"capability_spec": {}, "meta_spec": {}, "module_spec": {}, "requirement": {}, "submodule_spec": {}}, "requirement traceability graph specification node kind"); err != nil {
			return err
		}
	}
	if plane == "proof_coverage" {
		if node["kind"] != "scenario" {
			return fmt.Errorf("requirement traceability graph proof node kind must be scenario")
		}
		for _, key := range []string{"requirementId", "scenarioId", "witnessId", "witnessKind"} {
			if _, err := admit.RuleID(node[key], "requirement traceability graph proof node "+key); err != nil {
				return err
			}
		}
		witnessPath, err := admit.NonEmptyText(node["witnessPath"], "requirement traceability graph proof node witnessPath")
		if err != nil {
			return err
		}
		if _, err := admit.SafeRepoRelativePath(witnessPath, "requirement traceability graph proof node witnessPath"); err != nil {
			return err
		}
	}
	if err := admit.KnownKeys(node, keys, "requirement traceability graph node"); err != nil {
		return err
	}
	if _, err := admitGraphID(node["nodeId"], "requirement traceability graph nodeId"); err != nil {
		return err
	}
	if _, err := admit.NonEmptyText(node["label"], "requirement traceability graph node label"); err != nil {
		return err
	}
	if _, err := admit.NonEmptyText(node["kind"], "requirement traceability graph node kind"); err != nil {
		return err
	}
	if _, err := admit.NonEmptyText(node["sourceId"], "requirement traceability graph node sourceId"); err != nil {
		return err
	}
	if err := admitGraphNodeIdentity(node); err != nil {
		return err
	}
	if plane == "code_traceability" {
		if _, err := admit.Enum(node["kind"], map[string]struct{}{"file": {}, "module": {}, "package": {}, "repository": {}, "source_range": {}, "symbol": {}}, "requirement traceability graph code node kind"); err != nil {
			return err
		}
		if _, err := admit.Enum(node["currentnessState"], map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}, "requirement traceability graph code node currentnessState"); err != nil {
			return err
		}
		if _, err := digestRef(node["sourceDigest"], "requirement traceability graph code node sourceDigest"); err != nil {
			return err
		}
		if node["kind"] == "source_range" {
			if node["coordinateUnit"] != "utf8_byte" {
				return fmt.Errorf("requirement traceability graph range coordinateUnit must be utf8_byte")
			}
			if _, err := admit.Enum(node["rangeVerification"], map[string]struct{}{"unverified": {}, "verified": {}}, "requirement traceability graph rangeVerification"); err != nil {
				return err
			}
			start, err := nonNegativeInteger(node["byteStart"], "requirement traceability graph byteStart")
			if err != nil {
				return err
			}
			end, err := nonNegativeInteger(node["byteEnd"], "requirement traceability graph byteEnd")
			if err != nil || end <= start {
				return fmt.Errorf("requirement traceability graph range must be non-empty and half-open")
			}
		}
	}
	if plane == "native_execution_coverage" {
		if _, err := admit.Enum(node["authorityClass"], map[string]struct{}{"caller_reported": {}, "receipt_admitted": {}}, "requirement traceability graph execution authorityClass"); err != nil {
			return err
		}
		if _, err := admit.Enum(node["currentnessState"], map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}, "requirement traceability graph execution currentnessState"); err != nil {
			return err
		}
		if _, err := admit.Enum(node["state"], map[string]struct{}{"failed": {}, "passed": {}, "skipped": {}, "unavailable": {}}, "requirement traceability graph execution state"); err != nil {
			return err
		}
		if _, err := admit.RuleID(node["producerId"], "requirement traceability graph execution producerId"); err != nil {
			return err
		}
	}
	return nil
}

func admitGraphEdge(edge map[string]any) error {
	plane, err := admit.Enum(edge["evidencePlane"], map[string]struct{}{"code_traceability": {}, "native_execution_coverage": {}, "proof_coverage": {}, "specification_coverage": {}}, "requirement traceability graph edge evidencePlane")
	if err != nil {
		return err
	}
	keys := []string{"edgeId", "edgeKind", "evidencePlane", "fromNodeId", "toNodeId"}
	if plane == "code_traceability" && edge["edgeKind"] == "traced_to" {
		keys = append(keys, "authorityClass", "currentnessState", "evidenceRefs")
	}
	if plane == "native_execution_coverage" && edge["edgeKind"] == "observed_by" {
		keys = append(keys, "codeNodeId")
	}
	if plane == "native_execution_coverage" && edge["edgeKind"] == "observed_by" {
		if _, err := admit.RuleID(edge["codeNodeId"], "requirement traceability graph edge codeNodeId"); err != nil {
			return err
		}
	}
	if err := admit.KnownKeys(edge, keys, "requirement traceability graph edge"); err != nil {
		return err
	}
	if _, err := admitGraphID(edge["edgeId"], "requirement traceability graph edgeId"); err != nil {
		return err
	}
	if _, err := admit.Enum(edge["edgeKind"], map[string]struct{}{"contains": {}, "declares": {}, "observed_by": {}, "proved_by_candidate": {}, "traced_to": {}}, "requirement traceability graph edgeKind"); err != nil {
		return err
	}
	for _, key := range []string{"fromNodeId", "toNodeId"} {
		if _, err := admit.RuleID(edge[key], "requirement traceability graph edge "+key); err != nil {
			return err
		}
	}
	if plane == "code_traceability" && edge["edgeKind"] == "traced_to" {
		if _, err := admit.Enum(edge["authorityClass"], map[string]struct{}{"caller_reported": {}, "owner_admitted": {}}, "requirement traceability graph edge authorityClass"); err != nil {
			return err
		}
		if _, err := admit.Enum(edge["currentnessState"], map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}, "requirement traceability graph edge currentnessState"); err != nil {
			return err
		}
		values, err := admittedRuleIDArray(edge["evidenceRefs"], "requirement traceability graph edge evidenceRefs")
		if err != nil || len(values) == 0 {
			return fmt.Errorf("requirement traceability graph edge evidenceRefs must be non-empty")
		}
	}
	if err := admitGraphEdgeIdentity(edge); err != nil {
		return err
	}
	return nil
}

func admitGraphNodeIdentity(node map[string]any) error {
	nodeID := node["nodeId"].(string)
	sourceID := node["sourceId"].(string)
	switch node["evidencePlane"] {
	case "specification_coverage":
		if node["kind"] == "requirement" {
			if nodeID != "requirement:"+sourceID || node["label"] != sourceID {
				return fmt.Errorf("requirement traceability graph requirement node identity is invalid")
			}
		} else if nodeID != "spec:"+sourceID {
			return fmt.Errorf("requirement traceability graph specification node identity is invalid")
		}
	case "proof_coverage":
		identity := map[string]any{"requirementId": node["requirementId"], "scenarioId": node["scenarioId"], "witnessId": node["witnessId"], "witnessKind": node["witnessKind"], "witnessPath": node["witnessPath"]}
		expected, err := semanticGraphID("proof", identity)
		if err != nil || nodeID != expected || node["label"] != node["scenarioId"] || sourceID != node["witnessId"] {
			return fmt.Errorf("requirement traceability graph proof node identity is invalid")
		}
	case "native_execution_coverage":
		if nodeID != "execution:"+sourceID || node["label"] != sourceID {
			return fmt.Errorf("requirement traceability graph execution node identity is invalid")
		}
	}
	return nil
}

func admitGraphEdgeIdentity(edge map[string]any) error {
	edgeID := edge["edgeId"].(string)
	fromID := edge["fromNodeId"].(string)
	toID := edge["toNodeId"].(string)
	prefix := strings.SplitN(edgeID, ":", 2)[0]
	var identity map[string]any
	switch prefix {
	case "spec-edge", "declaration-edge", "code-parent-edge":
		identity = map[string]any{"edgeKind": edge["edgeKind"], "fromNodeId": fromID, "toNodeId": toID}
	case "proof-edge":
		identity = map[string]any{"fromNodeId": fromID, "toNodeId": toID}
	case "code-edge":
		identity = map[string]any{"authorityClass": edge["authorityClass"], "codeNodeId": strings.TrimPrefix(toID, "code:"), "currentnessState": edge["currentnessState"], "evidenceRefs": edge["evidenceRefs"], "requirementId": strings.TrimPrefix(fromID, "requirement:")}
	case "execution-edge":
		identity = map[string]any{"codeNodeId": strings.TrimPrefix(edge["codeNodeId"].(string), "code:"), "evidenceRef": strings.TrimPrefix(toID, "execution:"), "requirementId": strings.TrimPrefix(fromID, "requirement:")}
	default:
		return nil
	}
	expected, err := semanticGraphID(prefix, identity)
	if err != nil || edgeID != expected {
		return fmt.Errorf("requirement traceability graph edge identity is invalid")
	}
	return nil
}

func admitGraphID(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if ok && derivedGraphIDPattern.MatchString(value) {
		return value, nil
	}
	return admit.RuleID(raw, context)
}

func admitGraphRelation(edge map[string]any, nodes map[string]map[string]any) error {
	from := nodes[edge["fromNodeId"].(string)]
	to := nodes[edge["toNodeId"].(string)]
	if from == nil || to == nil {
		return fmt.Errorf("requirement traceability graph edge endpoint must resolve")
	}
	plane := edge["evidencePlane"].(string)
	kind := edge["edgeKind"].(string)
	valid := false
	switch plane + ":" + kind {
	case "specification_coverage:contains":
		valid = from["evidencePlane"] == plane && to["evidencePlane"] == plane && from["kind"] != "requirement" && to["kind"] != "requirement"
	case "specification_coverage:declares":
		valid = from["evidencePlane"] == plane && from["kind"] != "requirement" && to["evidencePlane"] == plane && to["kind"] == "requirement"
	case "proof_coverage:proved_by_candidate":
		valid = from["evidencePlane"] == "specification_coverage" && from["kind"] == "requirement" && to["evidencePlane"] == plane && to["kind"] == "scenario"
	case "code_traceability:contains":
		valid = from["evidencePlane"] == plane && to["evidencePlane"] == plane
	case "code_traceability:traced_to":
		valid = from["evidencePlane"] == "specification_coverage" && from["kind"] == "requirement" && to["evidencePlane"] == plane
	case "native_execution_coverage:observed_by":
		codeNode := nodes[edge["codeNodeId"].(string)]
		valid = from["evidencePlane"] == "specification_coverage" && from["kind"] == "requirement" && to["evidencePlane"] == plane && codeNode != nil && codeNode["evidencePlane"] == "code_traceability"
	}
	if !valid {
		return fmt.Errorf("requirement traceability graph relation is incompatible with its evidence plane and endpoint kinds")
	}
	return nil
}

func exactGraphNonClaims(raw any) error {
	values, ok := raw.([]any)
	if !ok || len(values) != len(nonClaims) {
		return fmt.Errorf("requirement traceability graph nonClaims must equal the command-owned boundary")
	}
	for index, expected := range nonClaims {
		if values[index] != expected {
			return fmt.Errorf("requirement traceability graph nonClaims must equal the command-owned boundary")
		}
	}
	return nil
}

func graphCountEquals(raw any, expected int) bool {
	if value, ok := raw.(int); ok {
		return value == expected
	}
	number, ok := raw.(json.Number)
	if !ok {
		return false
	}
	if expected == 0 {
		return admit.JSONNumberEquals(number, 0)
	}
	value, err := admit.PositiveInteger(number, "graph count")
	return err == nil && value == expected
}
