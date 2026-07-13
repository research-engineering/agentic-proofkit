package browserfixture

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const RequirementID = "REQ-CONSUMER-001"

func Workspace() (map[string]any, error) {
	base, err := snapshot("The system preserves the original semantic identity.")
	if err != nil {
		return nil, err
	}
	current, err := snapshot("The system preserves semantic identity for retry \U0001F680.")
	if err != nil {
		return nil, err
	}
	diffInput := map[string]any{
		"baseContext": base, "currentContext": current, "diffId": "browser.fixture.diff",
		"query": map[string]any{"requirementIds": []any{RequirementID}}, "schemaVersion": json.Number("1"),
	}
	code := "package retry\n\nfunc Retry() {}\n"
	start := strings.Index(code, "func Retry")
	graphInput := map[string]any{
		"codeSources": []any{map[string]any{"content": code, "path": "src/retry.go"}},
		"codeTopology": map[string]any{
			"edges": []any{map[string]any{"authorityClass": "owner_admitted", "codeNodeId": "code.retry", "currentnessState": "current", "evidenceRefs": []any{"browser.fixture.trace"}, "requirementId": RequirementID}},
			"nativeCoverage": []any{
				map[string]any{"authorityClass": "caller_reported", "codeNodeId": "code.retry", "currentnessState": "unverified", "evidenceRef": "browser.fixture.candidate", "producerId": "browser.fixture.candidate-runner", "requirementId": RequirementID, "state": "failed"},
				map[string]any{"authorityClass": "receipt_admitted", "codeNodeId": "code.retry", "currentnessState": "current", "evidenceRef": "browser.fixture.execution", "producerId": "browser.fixture.runner", "requirementId": RequirementID, "state": "passed"},
			},
			"nodes": []any{
				map[string]any{"abstractionLevel": "repository", "currentnessState": "stale", "label": "Fixture repository with a deliberately long traceability label preserved in the accessible title", "nodeId": "code.repository", "sourceDigest": digest.SHA256TextRef(code), "sourcePath": "src/retry.go"},
				map[string]any{"abstractionLevel": "source_range", "byteEnd": json.Number(fmt.Sprint(start + len("func Retry() {}"))), "byteStart": json.Number(fmt.Sprint(start)), "currentnessState": "current", "label": "Retry", "nodeId": "code.retry", "parentNodeId": "code.repository", "sourceDigest": digest.SHA256TextRef(code), "sourcePath": "src/retry.go"},
			},
		},
		"context": current, "graphId": "browser.fixture.graph", "schemaVersion": json.Number("2"),
	}
	return map[string]any{"context": current, "diffInput": diffInput, "graphInput": graphInput, "schemaVersion": json.Number("1"), "workspaceId": "browser.fixture.workspace"}, nil
}

func snapshot(invariant string) (map[string]any, error) {
	tree := map[string]any{"callerAnnotations": []any{}, "edges": []any{}, "nodes": []any{map[string]any{"callerAnnotations": []any{}, "displayOrder": json.Number("1"), "label": "Fixture specification", "nodeId": "spec.root", "nodeKind": "meta_spec", "sourceRefs": []any{map[string]any{"sourceId": "browser.fixture.requirements", "sourceRefId": "spec.root.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements"}}}}, "overlays": []any{}, "rootNodeId": "spec.root", "schemaVersion": json.Number("2"), "treeId": "browser.fixture.tree"}
	requirementSource := map[string]any{
		"nonClaims": []any{"Fixture requirements do not approve merge."}, "overviewPath": "docs/specs/browser-fixture/overview.md",
		"requirements":     []any{map[string]any{"claimLevel": "blocking", "invariant": invariant, "lifecycle": map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"}, "nonClaimRefs": []any{"NC-CONSUMER-001"}, "nonClaims": []any{"This requirement does not approve merge."}, "ownerId": "browser.fixture.owner", "proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "requirementId": RequirementID, "riskClass": "high", "updatePolicy": map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": "browser.fixture.owner"}}},
		"requirementsPath": "docs/specs/browser-fixture/requirements.v1.json", "schemaVersion": json.Number("1"), "sourceId": "browser.fixture.requirements", "specPackagePath": "docs/specs/browser-fixture",
	}
	projections := map[string]any{"requirementSources": []any{requirementSource}, "specTree": tree}
	treeBytes, err := stablejson.Marshal(tree)
	if err != nil {
		return nil, err
	}
	sources := []requirementcontext.Source{
		{CurrentDigest: digest.SHA256TextRef(invariant), Kind: "requirement_source", NodeID: "spec.root", Path: "docs/specs/browser-fixture/requirements.v1.json", SourceRef: "browser.fixture.requirements", SourceRole: "requirements"},
		{CurrentDigest: digest.SHA256TextRef(string(treeBytes)), Kind: "spec_tree", Path: "proofkit/browser-fixture-tree.json", SourceRef: "spec_tree:browser.fixture.tree"},
	}
	identity := map[string]any{"catalogId": "browser.fixture.context", "projections": projections, "sources": []any{map[string]any{"currentDigest": sources[0].CurrentDigest, "expectedDigest": "", "kind": sources[0].Kind, "nodeId": sources[0].NodeID, "path": sources[0].Path, "sourceRef": sources[0].SourceRef, "sourceRole": sources[0].SourceRole}, map[string]any{"currentDigest": sources[1].CurrentDigest, "expectedDigest": "", "kind": sources[1].Kind, "path": sources[1].Path, "sourceRef": sources[1].SourceRef}}}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		return nil, err
	}
	return requirementcontext.SnapshotValue(requirementcontext.Snapshot{BaselineVerification: "unverified", CatalogID: "browser.fixture.context", Projections: projections, SnapshotID: digest.SHA256TextRef(string(encoded)), Sources: sources}), nil
}
