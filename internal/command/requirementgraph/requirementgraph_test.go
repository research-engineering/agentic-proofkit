package requirementgraph

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
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
		"schemaVersion": json.Number("1"), "graphId": "consumer.traceability", "context": contextValue,
		"codeSources": []any{map[string]any{"path": "src/handler.go", "content": code}},
		"codeTopology": map[string]any{
			"topologyId": "consumer.code-topology",
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
}

func graphPermutationInput(t *testing.T) map[string]any {
	t.Helper()
	contextValue := graphContextFixture(t)
	code := "package handler\n\nfunc Handle() { return }\n"
	codeDigest := digest.SHA256TextRef(code)
	return map[string]any{
		"schemaVersion": json.Number("1"), "graphId": "consumer.traceability.permutation", "context": contextValue,
		"codeSources": []any{map[string]any{"path": "src/handler.go", "content": code}},
		"codeTopology": map[string]any{
			"topologyId": "consumer.code-topology.permutation",
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
