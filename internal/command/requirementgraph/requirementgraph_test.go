package requirementgraph

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildKeepsTraceabilityEvidencePlanesDistinct(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.040236281331857613367866543934119806645341297834533138126303789519826727502569")
	contextValue := graphContextFixture(t)
	code := "package handler\n\nfunc Handle() { return }\n"
	codeDigest := digest.SHA256TextRef(code)
	output, err := Build(map[string]any{
		"schemaVersion": json.Number("2"), "graphId": "consumer.traceability", "context": contextValue,
		"codeSources": []any{map[string]any{"path": "src/handler.go", "content": code}},
		"codeTopology": map[string]any{
			"nodes": []any{
				map[string]any{"nodeId": "code.repository", "abstractionLevel": "repository", "label": "Repository", "sourcePath": "src/handler.go", "sourceDigest": codeDigest, "currentnessState": "current"},
				map[string]any{"nodeId": "code.handler", "parentNodeId": "code.repository", "abstractionLevel": "source_range", "label": "Handle", "sourcePath": "src/handler.go", "sourceDigest": codeDigest, "currentnessState": "current", "byteStart": json.Number("17"), "byteEnd": json.Number("30")},
			},
			"edges":          []any{map[string]any{"codeNodeId": "code.handler", "requirementId": "REQ-CONSUMER-001", "evidenceRefs": []any{"consumer.trace.handler"}, "authorityClass": "caller_reported", "currentnessState": "current"}},
			"nativeCoverage": []any{map[string]any{"codeNodeId": "code.handler", "requirementId": "REQ-CONSUMER-001", "evidenceRef": "consumer.test.handler", "producerId": "consumer.test-runner", "authorityClass": "caller_reported", "currentnessState": "current", "state": "passed"}},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	planes := map[string]struct{}{}
	for _, raw := range output["nodes"].([]any) {
		planes[raw.(map[string]any)["evidencePlane"].(string)] = struct{}{}
	}
	for _, expected := range []string{"code_traceability", "native_execution_coverage", "proof_coverage", "specification_coverage"} {
		if _, ok := planes[expected]; !ok {
			t.Fatalf("missing evidence plane %s: %v", expected, planes)
		}
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitOutput(decoded, contextValue["snapshotId"].(string)); err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	for _, raw := range decoded.(map[string]any)["nodes"].([]any) {
		node := raw.(map[string]any)
		if node["evidencePlane"] == "proof_coverage" {
			node["scenarioId"] = "consumer.scenario.tampered"
			break
		}
	}
	if _, err := AdmitOutput(decoded, contextValue["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted proof node facts that do not match nodeId")
	}
}

func TestAdmitOutputRejectsDanglingAndIncoherentCodeParents(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.093487220897786293104017571940100080664662437591187487146507089441802769113895")
	output, err := Build(graphPermutationInput(t))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("dangling parent", func(t *testing.T) {
		record := decodedGraphOutput(t, output)
		for _, raw := range record["nodes"].([]any) {
			node := raw.(map[string]any)
			if node["kind"] == "source_range" {
				node["parentNodeId"] = "code:missing"
				break
			}
		}
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "parent") {
			t.Fatalf("AdmitOutput() error = %v, want unresolved parent rejection", err)
		}
	})

	t.Run("missing parent edge", func(t *testing.T) {
		record := decodedGraphOutput(t, output)
		edges := record["edges"].([]any)
		filtered := make([]any, 0, len(edges)-1)
		for _, raw := range edges {
			edge := raw.(map[string]any)
			if edge["evidencePlane"] == "code_traceability" && edge["edgeKind"] == "contains" {
				continue
			}
			filtered = append(filtered, edge)
		}
		record["edges"] = filtered
		record["edgeCount"] = json.Number(strconv.Itoa(len(filtered)))
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "parent") {
			t.Fatalf("AdmitOutput() error = %v, want missing parent edge rejection", err)
		}
	})

	t.Run("second parent edge", func(t *testing.T) {
		record := decodedGraphOutput(t, output)
		child := graphCodeNodeByKind(t, record, "source_range")
		root := graphCodeNodeByKind(t, record, "repository")
		secondRootID := "code:code.second-repository"
		appendGraphNode(record, map[string]any{
			"currentnessState": root["currentnessState"], "evidencePlane": "code_traceability", "kind": "repository",
			"label": "Second repository", "nodeId": secondRootID, "sourceDigest": root["sourceDigest"], "sourceId": root["sourceId"],
		})
		appendCodeParentEdge(t, record, secondRootID, child["nodeId"].(string))
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "exactly one parent edge") {
			t.Fatalf("AdmitOutput() error = %v, want second parent edge rejection", err)
		}
	})

	t.Run("parent field and edge mismatch", func(t *testing.T) {
		record := decodedGraphOutput(t, output)
		root := graphCodeNodeByKind(t, record, "repository")
		secondRootID := "code:code.second-repository"
		appendGraphNode(record, map[string]any{
			"currentnessState": root["currentnessState"], "evidencePlane": "code_traceability", "kind": "repository",
			"label": "Second repository", "nodeId": secondRootID, "sourceDigest": root["sourceDigest"], "sourceId": root["sourceId"],
		})
		graphCodeNodeByKind(t, record, "source_range")["parentNodeId"] = secondRootID
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "parentNodeId must match") {
			t.Fatalf("AdmitOutput() error = %v, want parent field and edge mismatch rejection", err)
		}
	})

	t.Run("parent abstraction is not broader", func(t *testing.T) {
		record := decodedGraphOutput(t, output)
		parent := graphCodeNodeByKind(t, record, "source_range")
		for _, key := range []string{"byteEnd", "byteStart", "coordinateUnit", "rangeVerification"} {
			delete(parent, key)
		}
		parent["kind"] = "package"
		childID := "code:code.same-level"
		appendGraphNode(record, map[string]any{
			"currentnessState": parent["currentnessState"], "evidencePlane": "code_traceability", "kind": "package",
			"label": "Same-level child", "nodeId": childID, "parentNodeId": parent["nodeId"],
			"sourceDigest": parent["sourceDigest"], "sourceId": parent["sourceId"],
		})
		appendCodeParentEdge(t, record, parent["nodeId"].(string), childID)
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "abstraction level") {
			t.Fatalf("AdmitOutput() error = %v, want parent abstraction rejection", err)
		}
	})
}

func TestAdmitOutputRejectsFieldsAndKindsOutsideTheirEvidencePlane(t *testing.T) {
	output, err := Build(graphPermutationInput(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"file", "module", "package", "repository", "symbol"} {
		t.Run("range fields on "+kind, func(t *testing.T) {
			record := decodedGraphOutput(t, output)
			node := graphCodeNodeByKind(t, record, "repository")
			node["kind"] = kind
			node["byteStart"] = json.Number("0")
			node["byteEnd"] = json.Number("1")
			node["coordinateUnit"] = "utf8_byte"
			node["rangeVerification"] = "unverified"
			if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "range fields") {
				t.Fatalf("AdmitOutput() error = %v, want non-range field rejection", err)
			}
		})
	}

	t.Run("native execution kind", func(t *testing.T) {
		record := decodedGraphOutput(t, output)
		for _, raw := range record["nodes"].([]any) {
			node := raw.(map[string]any)
			if node["evidencePlane"] == "native_execution_coverage" {
				node["kind"] = "repository"
				break
			}
		}
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "execution node kind") {
			t.Fatalf("AdmitOutput() error = %v, want native execution kind rejection", err)
		}
	})
}

func TestBuildRejectsCodeSourceDigestMismatchAtEveryAbstractionLevel(t *testing.T) {
	for _, level := range []string{"repository", "package", "module", "file", "symbol", "source_range"} {
		t.Run(level, func(t *testing.T) {
			input := graphPermutationInput(t)
			nodes := input["codeTopology"].(map[string]any)["nodes"].([]any)
			target := nodes[0].(map[string]any)
			if level != "repository" {
				target = nodes[1].(map[string]any)
				target["abstractionLevel"] = level
				if level != "source_range" {
					delete(target, "byteStart")
					delete(target, "byteEnd")
				}
			}
			target["sourceDigest"] = "sha256:" + strings.Repeat("0", 64)
			if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "does not match codeSources content") {
				t.Fatalf("Build() error = %v, want source digest mismatch rejection", err)
			}
		})
	}
}

func TestBuildRejectsBudgetsBeforePerItemSemantics(t *testing.T) {
	t.Run("code nodes", func(t *testing.T) {
		input := map[string]any{
			"schemaVersion": json.Number("2"), "graphId": "consumer.traceability.node-budget", "context": graphContextFixture(t),
			"codeTopology": map[string]any{"nodes": make([]any, maxGraphNodes+1), "edges": []any{}},
		}
		if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "node or edge limit") {
			t.Fatalf("Build() error = %v, want node budget rejection before node admission", err)
		}
	})

	t.Run("code edges", func(t *testing.T) {
		input := map[string]any{
			"schemaVersion": json.Number("2"), "graphId": "consumer.traceability.edge-budget", "context": graphContextFixture(t),
			"codeTopology": map[string]any{"nodes": []any{}, "edges": make([]any, maxGraphEdges+1)},
		}
		if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "node or edge limit") {
			t.Fatalf("Build() error = %v, want edge budget rejection before edge admission", err)
		}
	})

	t.Run("code source bytes", func(t *testing.T) {
		oversizedInvalidUTF8 := strings.Repeat("x", maxCodeSourceBytes+1) + string([]byte{0xff})
		input := map[string]any{
			"schemaVersion": json.Number("2"), "graphId": "consumer.traceability.source-budget", "context": graphContextFixture(t),
			"codeSources": []any{map[string]any{"path": "../outside.go", "content": oversizedInvalidUTF8}},
		}
		if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "code sources exceed byte limit") {
			t.Fatalf("Build() error = %v, want byte budget rejection before path and UTF-8 admission", err)
		}
	})
}

func TestAdmitOutputRejectsBudgetsBeforePerItemSemantics(t *testing.T) {
	snapshotID := graphContextFixture(t)["snapshotId"].(string)
	for _, test := range []struct {
		name  string
		nodes []any
		edges []any
	}{
		{name: "nodes", nodes: make([]any, maxGraphNodes+1), edges: []any{}},
		{name: "edges", nodes: []any{}, edges: make([]any, maxGraphEdges+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := map[string]any{
				"schemaVersion": json.Number("1"), "graphId": "consumer.traceability.output-budget", "graphKind": "proofkit.requirement-traceability-graph", "snapshotId": snapshotID,
				"nodes": test.nodes, "nodeCount": json.Number(strconv.Itoa(len(test.nodes))), "edges": test.edges, "edgeCount": json.Number(strconv.Itoa(len(test.edges))), "nonClaims": admit.StringSliceToAny(nonClaims),
			}
			if _, err := AdmitOutput(record, snapshotID); err == nil || !strings.Contains(err.Error(), "node or edge limit") {
				t.Fatalf("AdmitOutput() error = %v, want budget rejection before record admission", err)
			}
		})
	}
}

func TestBuildRejectsSemanticallyInertTopologyID(t *testing.T) {
	input := graphPermutationInput(t)
	input["codeTopology"].(map[string]any)["topologyId"] = "consumer.code-topology"
	if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "unsupported field(s): topologyId") {
		t.Fatalf("Build() error = %v, want topologyId rejection", err)
	}
}

func TestBuildRequiresInputSchemaVersion2(t *testing.T) {
	input := graphPermutationInput(t)
	input["schemaVersion"] = json.Number("1")
	if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "input schemaVersion must be 2") {
		t.Fatalf("Build() error = %v, want old input schema rejection", err)
	}
}

func TestGraphIdentityIsPermutationStableAndRelationsAreTyped(t *testing.T) {
	input := graphPermutationInput(t)
	first, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	topology := input["codeTopology"].(map[string]any)
	edges := topology["edges"].([]any)
	edges[0], edges[1] = edges[1], edges[0]
	coverage := topology["nativeCoverage"].([]any)
	coverage[0], coverage[1] = coverage[1], coverage[0]
	second, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := stablejson.Marshal(first)
	secondJSON, _ := stablejson.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("semantic graph changed after caller array permutation")
	}

	tamperedRaw, err := admission.DecodeJSON(bytes.NewReader(firstJSON), int64(len(firstJSON)))
	if err != nil {
		t.Fatal(err)
	}
	tampered := tamperedRaw.(map[string]any)
	for _, raw := range tampered["edges"].([]any) {
		edge := raw.(map[string]any)
		if edge["edgeKind"] == "traced_to" {
			edge["evidencePlane"] = "native_execution_coverage"
			break
		}
	}
	if _, err := AdmitOutput(tampered, input["context"].(map[string]any)["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted an edge laundered into another evidence plane")
	}

	t.Run("edge identity class", func(t *testing.T) {
		record := decodedGraphOutput(t, first)
		for _, raw := range record["edges"].([]any) {
			edge := raw.(map[string]any)
			if edge["edgeKind"] == "contains" && edge["evidencePlane"] == "code_traceability" {
				edge["edgeId"] = strings.Replace(edge["edgeId"].(string), "code-parent-edge:", "spec-edge:", 1)
				break
			}
		}
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("AdmitOutput() error = %v, want edge identity-class rejection", err)
		}
	})

	t.Run("code node namespace", func(t *testing.T) {
		record := decodedGraphOutput(t, first)
		for _, raw := range record["nodes"].([]any) {
			node := raw.(map[string]any)
			if node["evidencePlane"] == "code_traceability" {
				node["nodeId"] = "forged.code-node"
				break
			}
		}
		if _, err := AdmitOutput(record, record["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("AdmitOutput() error = %v, want code namespace rejection", err)
		}
	})
}

func graphPermutationInput(t *testing.T) map[string]any {
	t.Helper()
	contextValue := graphContextFixture(t)
	code := "package handler\n\nfunc Handle() { return }\n"
	codeDigest := digest.SHA256TextRef(code)
	return map[string]any{
		"schemaVersion": json.Number("2"), "graphId": "consumer.traceability.permutation", "context": contextValue,
		"codeSources": []any{map[string]any{"path": "src/handler.go", "content": code}},
		"codeTopology": map[string]any{
			"nodes": []any{
				map[string]any{"nodeId": "code.repository", "abstractionLevel": "repository", "label": "Repository", "sourcePath": "src/handler.go", "sourceDigest": codeDigest, "currentnessState": "current"},
				map[string]any{"nodeId": "code.handler", "parentNodeId": "code.repository", "abstractionLevel": "source_range", "label": "Handle", "sourcePath": "src/handler.go", "sourceDigest": codeDigest, "currentnessState": "current", "byteStart": json.Number("17"), "byteEnd": json.Number("30")},
			},
			"edges": []any{
				map[string]any{"codeNodeId": "code.handler", "requirementId": "REQ-CONSUMER-001", "evidenceRefs": []any{"consumer.trace.a"}, "authorityClass": "caller_reported", "currentnessState": "current"},
				map[string]any{"codeNodeId": "code.handler", "requirementId": "REQ-CONSUMER-001", "evidenceRefs": []any{"consumer.trace.b"}, "authorityClass": "caller_reported", "currentnessState": "current"},
			},
			"nativeCoverage": []any{
				map[string]any{"codeNodeId": "code.handler", "requirementId": "REQ-CONSUMER-001", "evidenceRef": "consumer.test.a", "producerId": "consumer.test-runner", "authorityClass": "caller_reported", "currentnessState": "current", "state": "passed"},
				map[string]any{"codeNodeId": "code.handler", "requirementId": "REQ-CONSUMER-001", "evidenceRef": "consumer.test.b", "producerId": "consumer.test-runner", "authorityClass": "caller_reported", "currentnessState": "current", "state": "passed"},
			},
		},
	}
}

func decodedGraphOutput(t *testing.T, output map[string]any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func graphCodeNodeByKind(t *testing.T, record map[string]any, kind string) map[string]any {
	t.Helper()
	for _, raw := range record["nodes"].([]any) {
		node := raw.(map[string]any)
		if node["evidencePlane"] == "code_traceability" && node["kind"] == kind {
			return node
		}
	}
	t.Fatalf("code node kind %q is unavailable", kind)
	return nil
}

func appendGraphNode(record map[string]any, node map[string]any) {
	nodes := append(record["nodes"].([]any), node)
	sort.Slice(nodes, func(left, right int) bool {
		return nodes[left].(map[string]any)["nodeId"].(string) < nodes[right].(map[string]any)["nodeId"].(string)
	})
	record["nodes"] = nodes
	record["nodeCount"] = json.Number(strconv.Itoa(len(nodes)))
}

func appendCodeParentEdge(t *testing.T, record map[string]any, parentID, childID string) {
	t.Helper()
	edgeID, err := semanticGraphID("code-parent-edge", map[string]any{"edgeKind": "contains", "fromNodeId": parentID, "toNodeId": childID})
	if err != nil {
		t.Fatal(err)
	}
	edges := append(record["edges"].([]any), map[string]any{"edgeId": edgeID, "edgeKind": "contains", "evidencePlane": "code_traceability", "fromNodeId": parentID, "toNodeId": childID})
	sort.Slice(edges, func(left, right int) bool {
		return edges[left].(map[string]any)["edgeId"].(string) < edges[right].(map[string]any)["edgeId"].(string)
	})
	record["edges"] = edges
	record["edgeCount"] = json.Number(strconv.Itoa(len(edges)))
}

func graphContextFixture(t *testing.T) map[string]any {
	t.Helper()
	projections := map[string]any{
		"specTree": map[string]any{"schemaVersion": json.Number("2"), "treeId": "consumer.spec-tree", "rootNodeId": "spec.root", "callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{}, "nodes": []any{map[string]any{"nodeId": "spec.root", "nodeKind": "meta_spec", "label": "Root", "displayOrder": json.Number("1"), "callerAnnotations": []any{}, "sourceRefs": []any{map[string]any{"sourceRefId": "spec.root.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "consumer.requirements"}}}}},
		"requirementSources": []any{map[string]any{
			"schemaVersion": json.Number("1"), "sourceId": "consumer.requirements", "specPackagePath": "docs/specs/consumer", "overviewPath": "docs/specs/consumer/overview.md", "requirementsPath": "docs/specs/consumer/requirements.v1.json", "nonClaims": []any{"Consumer source does not approve merge."},
			"requirements": []any{map[string]any{"requirementId": "REQ-CONSUMER-001", "ownerId": "consumer.owner", "invariant": "The system preserves semantic identity.", "claimLevel": "blocking", "riskClass": "high", "proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "nonClaimRefs": []any{"NC-CONSUMER-001"}, "nonClaims": []any{"This requirement does not approve merge."}, "lifecycle": map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}}, "updatePolicy": map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true}}},
		}},
		"proofBinding": map[string]any{
			"schemaVersion": json.Number("1"), "bindingId": "consumer.proof-bindings",
			"requirements":    []any{map[string]any{"claimLevel": "blocking", "nonClaims": []any{"Fixture proof requirement does not approve merge."}, "ownerId": "consumer.owner", "proofState": "witness_backed", "requirementId": "REQ-CONSUMER-001", "specPath": "docs/specs/consumer/requirements.v1.json"}},
			"bindings":        []any{map[string]any{"commandIds": []any{"consumer.test"}, "environmentClasses": []any{"local-go"}, "requirementId": "REQ-CONSUMER-001", "scenarioId": "consumer.scenario", "witnessId": "consumer.witness", "witnessKind": "contract", "witnessPath": "internal/consumer_test.go"}},
			"witnessCommands": []any{map[string]any{"command": "go test ./internal", "commandId": "consumer.test", "environmentClass": "local-go"}},
			"selection":       map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}},
			"nonClaims":       []any{"Fixture proof bindings do not execute witnesses."},
		},
	}
	proofResult, err := requirementbinding.Build(projections["proofBinding"])
	if err != nil || proofResult.Record.State != "passed" {
		t.Fatalf("admit graph proof fixture: %v state=%v", err, proofResult.Record.State)
	}
	projections["proofBinding"] = requirementbinding.InputValue(proofResult.Input)
	sources := []requirementcontext.Source{{CurrentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "requirement_source", NodeID: "spec.root", Path: "docs/specs/consumer/requirements.v1.json", SourceRef: "consumer.requirements", SourceRole: "requirements"}, {CurrentDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Kind: "proof_binding", Path: "proofkit/requirement-bindings.json", SourceRef: "proof_binding:consumer.proof-bindings"}, {CurrentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Kind: "spec_tree", Path: "proofkit/spec-tree.json", SourceRef: "spec_tree:consumer.spec-tree"}}
	identity := map[string]any{"catalogId": "consumer.context", "projections": projections, "sources": []any{map[string]any{"currentDigest": sources[0].CurrentDigest, "expectedDigest": "", "kind": sources[0].Kind, "nodeId": sources[0].NodeID, "path": sources[0].Path, "sourceRef": sources[0].SourceRef, "sourceRole": sources[0].SourceRole}, map[string]any{"currentDigest": sources[1].CurrentDigest, "expectedDigest": "", "kind": sources[1].Kind, "path": sources[1].Path, "sourceRef": sources[1].SourceRef}, map[string]any{"currentDigest": sources[2].CurrentDigest, "expectedDigest": "", "kind": sources[2].Kind, "path": sources[2].Path, "sourceRef": sources[2].SourceRef}}}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	return requirementcontext.SnapshotValue(requirementcontext.Snapshot{BaselineVerification: "unverified", CatalogID: "consumer.context", Projections: projections, SnapshotID: digest.SHA256TextRef(string(encoded)), Sources: sources})
}
