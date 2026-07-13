package requirementcontext

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestSlicePreservesRequirementSourceRole(t *testing.T) {
	contextValue := sliceTopologyFixture(t)
	output, err := Slice(map[string]any{
		"context": contextValue, "schemaVersion": json.Number("1"), "sliceId": "consumer.role-slice",
		"query": map[string]any{"maxDepth": json.Number("0"), "nodeIds": []any{"spec.root"}, "profile": "specification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSelectedSourceIDs(t, output, "consumer.requirements-a")
	tree := output["projections"].(map[string]any)["specTree"].(map[string]any)
	refs := tree["nodes"].([]any)[0].(map[string]any)["sourceRefs"].([]any)
	if len(refs) != 3 || refs[0].(map[string]any)["sourceRole"] != "overview" || refs[1].(map[string]any)["sourceId"] != "consumer.requirements-a" || refs[2].(map[string]any)["sourceRefKind"] != "path_digest" {
		t.Fatalf("tree fragment lost source-role identity: %#v", refs)
	}
	overlays := tree["overlays"].([]any)
	if len(overlays) != 2 || overlays[0].(map[string]any)["refId"] != "spec.root.overview-b" || overlays[1].(map[string]any)["refId"] != "spec.root.requirements-path" {
		t.Fatalf("tree fragment lost retained source-ref overlay: %#v", overlays)
	}
}

func TestRoutingSliceRestrictsSourcesToSelectedTree(t *testing.T) {
	output, err := Slice(map[string]any{
		"context": sliceTopologyFixture(t), "schemaVersion": json.Number("1"), "sliceId": "consumer.routing-slice",
		"query": map[string]any{"maxNodes": json.Number("1"), "profile": "routing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSelectedSourceIDs(t, output, "consumer.requirements-a")
	omissions := output["omissions"].([]any)
	if len(omissions) != 1 || omissions[0].(map[string]any)["kind"] != "nodes" || omissions[0].(map[string]any)["count"] != 1 {
		t.Fatalf("routing omissions = %#v, want one max_nodes omission", omissions)
	}
}

func TestSliceSelectorIntersectionReturnsNoMatch(t *testing.T) {
	output, err := Slice(map[string]any{
		"context": sliceTopologyFixture(t), "schemaVersion": json.Number("1"), "sliceId": "consumer.empty-intersection",
		"query": map[string]any{"ownerIds": []any{"consumer.owner-b"}, "profile": "specification", "requirementIds": []any{"REQ-CONSUMER-A"}},
	})
	if err != nil {
		t.Fatalf("valid empty selector intersection was rejected: %v", err)
	}
	if output["state"] != "no_match" {
		t.Fatalf("state = %v, want no_match", output["state"])
	}
	assertSelectedSourceIDs(t, output)
}

func TestRequirementSelectorClosesTreeOverSelectedSource(t *testing.T) {
	contextValue := sliceTopologyFixture(t)
	input := map[string]any{
		"context": contextValue, "schemaVersion": json.Number("1"), "sliceId": "consumer.requirement-tree-closure",
		"query": map[string]any{"maxNodes": json.Number("2"), "profile": "specification", "requirementIds": []any{"REQ-CONSUMER-B"}},
	}
	output, err := Slice(input)
	if err != nil {
		t.Fatal(err)
	}
	assertSelectedSourceIDs(t, output, "consumer.requirements-b")
	nodes := output["projections"].(map[string]any)["specTree"].(map[string]any)["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("selected source node closure = %#v, want root and child", nodes)
	}
	input["query"].(map[string]any)["maxNodes"] = json.Number("1")
	if _, err := Slice(input); err == nil {
		t.Fatal("Slice accepted a bound that cannot retain selected source ancestor closure")
	}
}

func TestRequirementSelectorDoesNotReportInternalTreeDerivationAsOmission(t *testing.T) {
	output, err := Slice(map[string]any{
		"context": threeLevelSliceTopologyFixture(t, [3]int{1, 2, 3}), "schemaVersion": json.Number("1"), "sliceId": "consumer.requirement-derived-tree",
		"query": map[string]any{"maxNodes": json.Number("2"), "profile": "specification", "requirementIds": []any{"REQ-CONSUMER-B"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if omissions := output["omissions"].([]any); len(omissions) != 0 {
		t.Fatalf("internal source-node derivation leaked as caller omission: %#v", omissions)
	}
	nodes := output["projections"].(map[string]any)["specTree"].(map[string]any)["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("derived tree closure = %#v, want source node and ancestor only", nodes)
	}
}

func TestSliceNodeBoundsPreserveAncestorsAcrossDisplayOrders(t *testing.T) {
	orders := [][3]int{{1, 2, 3}, {3, 2, 1}, {2, 3, 1}, {2, 1, 3}}
	for _, order := range orders {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			contextValue := threeLevelSliceTopologyFixture(t, order)
			output, err := Slice(map[string]any{
				"context": contextValue, "schemaVersion": json.Number("1"), "sliceId": "consumer.ancestor-closure",
				"query": map[string]any{"maxNodes": json.Number("2"), "nodeIds": []any{"spec.root"}, "profile": "specification"},
			})
			if err != nil {
				t.Fatal(err)
			}
			nodes := output["projections"].(map[string]any)["specTree"].(map[string]any)["nodes"].([]any)
			selected := map[string]bool{}
			for _, raw := range nodes {
				selected[raw.(map[string]any)["nodeId"].(string)] = true
			}
			if !selected["spec.root"] || !selected["spec.child"] || selected["spec.grandchild"] {
				t.Fatalf("bounded selection lost ancestor closure: %#v", selected)
			}
		})
	}
}

func TestSliceReportsDepthAndNodeOmissionsAsDisjointSets(t *testing.T) {
	output, err := Slice(map[string]any{
		"context": threeLevelSliceTopologyFixture(t, [3]int{3, 2, 1}), "schemaVersion": json.Number("1"), "sliceId": "consumer.depth-omissions",
		"query": map[string]any{"maxDepth": json.Number("0"), "maxNodes": json.Number("1"), "nodeIds": []any{"spec.root"}, "profile": "specification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	omissions := output["omissions"].([]any)
	if len(omissions) != 1 || omissions[0].(map[string]any)["reason"] != "max_depth" || omissions[0].(map[string]any)["count"] != 2 {
		t.Fatalf("depth omissions = %#v, want two max_depth nodes", omissions)
	}
}

func threeLevelSliceTopologyFixture(t *testing.T, displayOrders [3]int) map[string]any {
	t.Helper()
	contextValue := sliceTopologyFixture(t)
	tree := contextValue["projections"].(map[string]any)["specTree"].(map[string]any)
	nodes := tree["nodes"].([]any)
	nodes[0].(map[string]any)["displayOrder"] = json.Number(fmt.Sprint(displayOrders[0]))
	nodes[1].(map[string]any)["displayOrder"] = json.Number(fmt.Sprint(displayOrders[1]))
	grandchild := map[string]any{
		"callerAnnotations": []any{}, "displayOrder": json.Number(fmt.Sprint(displayOrders[2])), "label": "Grandchild", "nodeId": "spec.grandchild", "nodeKind": "submodule_spec",
		"sourceRefs": []any{map[string]any{"sourceId": "consumer.requirements-b", "sourceRefId": "spec.grandchild.requirements-b", "sourceRefKind": "source_id", "sourceRole": "requirements"}},
	}
	tree["nodes"] = append(nodes, grandchild)
	tree["edges"] = append(tree["edges"].([]any), map[string]any{"childNodeId": "spec.grandchild", "parentNodeId": "spec.child"})
	canonicalizeAndResignSnapshot(t, contextValue)
	return contextValue
}

func canonicalizeAndResignSnapshot(t *testing.T, value map[string]any) {
	t.Helper()
	_, _, _, _, canonical, err := admitSnapshotProjections(value["projections"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	value["projections"] = canonical
	resignSnapshot(t, value)
}

func assertSelectedSourceIDs(t *testing.T, output map[string]any, expected ...string) {
	t.Helper()
	sources := output["projections"].(map[string]any)["requirementSources"].([]any)
	if len(sources) != len(expected) {
		t.Fatalf("selected sources = %#v, want %v", sources, expected)
	}
	for index, sourceID := range expected {
		if sources[index].(map[string]any)["sourceId"] != sourceID {
			t.Fatalf("selected sources = %#v, want %v", sources, expected)
		}
	}
}

func sliceTopologyFixture(t *testing.T) map[string]any {
	t.Helper()
	requirementA := sliceRequirement("REQ-CONSUMER-A", "consumer.owner-a", "blocking", "active", []any{})
	requirementB := sliceRequirement("REQ-CONSUMER-B", "consumer.owner-b", "blocking", "active", []any{})
	sourceA := sliceRequirementSource("consumer.requirements-a", requirementA)
	sourceB := sliceRequirementSource("consumer.requirements-b", requirementB)
	tree := map[string]any{
		"callerAnnotations": []any{},
		"edges":             []any{map[string]any{"childNodeId": "spec.child", "parentNodeId": "spec.root"}},
		"nodes": []any{
			map[string]any{"callerAnnotations": []any{}, "displayOrder": json.Number("1"), "label": "Root", "nodeId": "spec.root", "nodeKind": "meta_spec", "sourceRefs": []any{
				map[string]any{"sourceId": "consumer.requirements-b", "sourceRefId": "spec.root.overview-b", "sourceRefKind": "source_id", "sourceRole": "overview"},
				map[string]any{"sourceId": "consumer.requirements-a", "sourceRefId": "spec.root.requirements-a", "sourceRefKind": "source_id", "sourceRole": "requirements"},
				map[string]any{
					"currentSourceDigest": digest.SHA256TextRef("auxiliary"), "digestAlgorithm": "sha256",
					"recordedSourceDigest": digest.SHA256TextRef("auxiliary"), "sourcePath": "docs/specs/auxiliary/requirements.v1.json",
					"sourceRefId": "spec.root.requirements-path", "sourceRefKind": "path_digest", "sourceRole": "requirements",
				},
			}},
			map[string]any{"callerAnnotations": []any{}, "displayOrder": json.Number("2"), "label": "Child", "nodeId": "spec.child", "nodeKind": "module_spec", "sourceRefs": []any{
				map[string]any{"sourceId": "consumer.requirements-b", "sourceRefId": "spec.child.requirements-b", "sourceRefKind": "source_id", "sourceRole": "requirements"},
			}},
		},
		"overlays": []any{map[string]any{
			"callerAnnotations": []any{}, "label": "Root overview", "overlayId": "overlay.root.overview",
			"overlayKind": "source", "refId": "spec.root.overview-b", "refKind": "source_ref", "targetNodeId": "spec.root",
		}, map[string]any{
			"callerAnnotations": []any{}, "label": "Auxiliary requirements", "overlayId": "overlay.root.requirements-path",
			"overlayKind": "source", "refId": "spec.root.requirements-path", "refKind": "source_ref", "targetNodeId": "spec.root",
		}}, "rootNodeId": "spec.root", "schemaVersion": json.Number("2"), "treeId": "consumer.slice-tree",
	}
	projections := map[string]any{"requirementSources": []any{sourceA, sourceB}, "specTree": tree}
	sources := []Source{
		{CurrentDigest: digest.SHA256TextRef("consumer.requirements-a"), Kind: "requirement_source", NodeID: "spec.root", Path: "docs/specs/a/requirements.v1.json", SourceRef: "consumer.requirements-a", SourceRole: "requirements"},
		{CurrentDigest: digest.SHA256TextRef("consumer.requirements-b"), Kind: "requirement_source", NodeID: "spec.child", Path: "docs/specs/b/requirements.v1.json", SourceRef: "consumer.requirements-b", SourceRole: "requirements"},
		{CurrentDigest: digest.SHA256TextRef("consumer.slice-tree"), Kind: "spec_tree", Path: "proofkit/spec-tree.json", SourceRef: "spec_tree:consumer.slice-tree"},
	}
	identity, err := stablejson.Marshal(map[string]any{"catalogId": "consumer.slice-context", "projections": projections, "sources": sourceIdentityValues(sources)})
	if err != nil {
		t.Fatal(err)
	}
	return SnapshotValue(Snapshot{BaselineVerification: "unverified", CatalogID: "consumer.slice-context", Projections: projections, SnapshotID: digest.SHA256TextRef(string(identity)), Sources: sources})
}

func sliceRequirement(id, owner, claimLevel, lifecycleState string, replacementIDs []any) map[string]any {
	return map[string]any{
		"claimLevel": claimLevel, "invariant": "The selected contract remains explicit.",
		"lifecycle":    map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": replacementIDs, "state": lifecycleState},
		"nonClaimRefs": []any{"NC-CONSUMER-001"}, "nonClaims": []any{"This requirement does not approve merge."},
		"ownerId": owner, "proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "requirementId": id, "riskClass": "high",
		"updatePolicy": map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": owner},
	}
}

func sliceRequirementSource(sourceID string, requirement map[string]any) map[string]any {
	return map[string]any{
		"nonClaims": []any{"Consumer source does not approve merge."}, "overviewPath": "docs/specs/consumer/overview.md",
		"requirements": []any{requirement}, "requirementsPath": "docs/specs/consumer/requirements.v1.json",
		"schemaVersion": json.Number("1"), "sourceId": sourceID, "specPackagePath": "docs/specs/consumer",
	}
}
