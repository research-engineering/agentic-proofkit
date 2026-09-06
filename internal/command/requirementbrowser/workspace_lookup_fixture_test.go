package requirementbrowser

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func workspaceLookupFixture(t *testing.T) map[string]any {
	t.Helper()
	fixture := workspaceFixture(t)
	contextValue := fixture["context"].(map[string]any)
	projections := contextValue["projections"].(map[string]any)
	template := projections["requirementSources"].([]any)[0].(map[string]any)
	requirementTemplate := template["requirements"].([]any)[0].(map[string]any)
	makeRequirement := func(id, owner, invariant string) map[string]any {
		record := cloneWorkspaceRecord(t, requirementTemplate)
		record["requirementId"], record["ownerId"], record["invariant"] = id, owner, invariant
		record["updatePolicy"].(map[string]any)["reviewOwnerId"] = owner
		return record
	}
	makeSource := func(name string, requirements []any) map[string]any {
		source := cloneWorkspaceRecord(t, template)
		source["sourceId"] = "consumer." + name
		source["specPackagePath"] = "docs/specs/" + name
		source["overviewPath"] = "docs/specs/" + name + "/overview.md"
		source["requirementsPath"] = "docs/specs/" + name + "/requirements.v1.json"
		source["requirements"] = requirements
		return source
	}
	rows := make([]any, 130)
	for index := range rows {
		rows[index] = makeRequirement(fmt.Sprintf("REQ-B-%03d", index), "owner.b", fmt.Sprintf("Capability %03d remains explicit.", index))
	}
	rows[0].(map[string]any)["claimLevel"] = "advisory"
	rows[0].(map[string]any)["lifecycle"] = map[string]any{"state": "superseded", "replacementRequirementIds": []any{"REQ-B-001"}, "evidenceRefs": []any{"consumer.migration"}}
	rows[1].(map[string]any)["ownerId"] = "owner.c"
	rows[1].(map[string]any)["updatePolicy"].(map[string]any)["reviewOwnerId"] = "owner.c"
	rows[129].(map[string]any)["invariant"] = "State \U0001f9ed e\u0301 keeps source identity."
	projections["requirementSources"] = []any{
		makeSource("a", []any{makeRequirement("REQ-A", "owner.a", "The root contract remains explicit.")}),
		makeSource("b", rows),
		makeSource("c", []any{makeRequirement("REQ-C", "owner.c", "The nested contract remains explicit.")}),
	}
	ref := func(id, role, source string) map[string]any {
		return map[string]any{"sourceRefId": id, "sourceRefKind": "source_id", "sourceRole": role, "sourceId": source}
	}
	pathRef := func(id, role string) map[string]any {
		return map[string]any{"sourceRefId": id, "sourceRefKind": "path_digest", "sourceRole": role, "sourcePath": "docs/auxiliary.md", "digestAlgorithm": "sha256", "recordedSourceDigest": digest.SHA256TextRef("auxiliary"), "currentSourceDigest": digest.SHA256TextRef("auxiliary")}
	}
	node := func(id, label, kind string, order int, refs []any) map[string]any {
		return map[string]any{"nodeId": id, "label": label, "nodeKind": kind, "displayOrder": json.Number(fmt.Sprint(order)), "callerAnnotations": []any{}, "sourceRefs": refs}
	}
	tree := projections["specTree"].(map[string]any)
	tree["nodes"] = []any{
		node("spec.root", "Workspace root", "meta_spec", 50, []any{ref("root.requirements", "requirements", "consumer.a"), pathRef("root.path-a", "requirements"), pathRef("root.path-b", "overview")}),
		node("spec.child", "Child contracts", "module_spec", 10, []any{ref("child.requirements", "requirements", "consumer.b"), ref("child.overview", "overview", "consumer.a")}),
		node("spec.grandchild", "Nested contracts", "submodule_spec", 90, []any{ref("grandchild.requirements", "requirements", "consumer.c"), ref("grandchild.overview", "overview", "consumer.b")}),
	}
	tree["edges"] = []any{map[string]any{"parentNodeId": "spec.root", "childNodeId": "spec.child"}, map[string]any{"parentNodeId": "spec.child", "childNodeId": "spec.grandchild"}}
	tree["overlays"] = []any{
		map[string]any{"overlayId": "overlay.path-a", "overlayKind": "source", "label": "Auxiliary requirements", "refKind": "source_ref", "refId": "root.path-a", "targetNodeId": "spec.root", "callerAnnotations": []any{}},
		map[string]any{"overlayId": "overlay.path-b", "overlayKind": "source", "label": "Auxiliary overview", "refKind": "source_ref", "refId": "root.path-b", "targetNodeId": "spec.root", "callerAnnotations": []any{}},
	}
	contextValue["sources"] = []any{
		map[string]any{"currentDigest": digest.SHA256TextRef("source-a"), "kind": "requirement_source", "nodeId": "spec.root", "path": "docs/specs/a/requirements.v1.json", "sourceRef": "consumer.a", "sourceRole": "requirements"},
		map[string]any{"currentDigest": digest.SHA256TextRef("source-b"), "kind": "requirement_source", "nodeId": "spec.child", "path": "docs/specs/b/requirements.v1.json", "sourceRef": "consumer.b", "sourceRole": "requirements"},
		map[string]any{"currentDigest": digest.SHA256TextRef("source-c"), "kind": "requirement_source", "nodeId": "spec.grandchild", "path": "docs/specs/c/requirements.v1.json", "sourceRef": "consumer.c", "sourceRole": "requirements"},
		map[string]any{"currentDigest": digest.SHA256TextRef("tree"), "kind": "spec_tree", "path": "proofkit/spec-tree.json", "sourceRef": "spec_tree:consumer.spec-tree"},
	}
	resignWorkspaceSnapshot(t, contextValue)
	return fixture
}
