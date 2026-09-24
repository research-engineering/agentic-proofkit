package browserfixture

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func LookupWorkspace() (map[string]any, error) {
	return lookupWorkspace(130)
}

func CapacityWorkspace() (map[string]any, error) {
	return lookupWorkspace(3709)
}

func lookupWorkspace(siblingCount int) (map[string]any, error) {
	contextValue, err := snapshot("Root scope remains independent.", "high")
	if err != nil {
		return nil, err
	}
	projections := contextValue["projections"].(map[string]any)
	template := projections["requirementSources"].([]any)[0].(map[string]any)
	groupTemplate := template["groups"].([]any)[0].(map[string]any)
	rowTemplate := groupTemplate["members"].([]any)[0].(map[string]any)
	row := func(id, owner, invariant string) map[string]any {
		value := maps.Clone(rowTemplate)
		value["requirementId"], value["statementCompletion"] = id, invariant
		fields := maps.Clone(rowTemplate["fields"].(map[string]any))
		fields["ownerId"] = owner
		fields["updatePolicy"] = map[string]any{"reviewOwnerId": owner, "requiresImpactDeclaration": true, "requiresProofBindingReview": true}
		value["fields"] = fields
		return value
	}
	rows := make([]any, 130)
	for index := range rows {
		rows[index] = row(fmt.Sprintf("REQ-B-%03d", index), "owner.b", fmt.Sprintf("Capability %03d remains explicit.", index))
	}
	rows[0].(map[string]any)["fields"].(map[string]any)["claimLevel"] = "advisory"
	rows[0].(map[string]any)["fields"].(map[string]any)["lifecycle"] = map[string]any{"state": "superseded", "replacementRequirementIds": []any{"REQ-B-001"}, "evidenceRefs": []any{"consumer.migration"}}
	rows[1] = row("REQ-B-001", "owner.c", "Capability 001 remains explicit.")
	rows[129] = row("REQ-B-129", "owner.b", "State \U0001f9ed e\u0301 keeps source identity.")
	inputs := []struct {
		id, node string
		rows     []any
	}{
		{"a", "spec.root", []any{row("REQ-A", "owner.a", "Root scope remains independent.")}},
		{"b", "spec.child", rows},
		{"c", "spec.grandchild", []any{row("REQ-C", "owner.c", "Nested scope remains independent.")}},
	}
	sources, identitySources, requirementSources := []any{}, []any{}, []any{}
	for _, input := range inputs {
		source := maps.Clone(template)
		source["sourceId"] = "consumer." + input.id
		group := maps.Clone(groupTemplate)
		group["members"] = input.rows
		source["groups"] = []any{group}
		if input.id == "b" {
			// Preserve the authored effective texts while exercising real shared
			// stems in browser witnesses. The final Unicode row is independent.
			group["groupId"], group["statementStem"] = "RGRP-CAPABILITIES", "Capability"
			group["sharedPremises"] = []any{"Only the selected caller scope applies."}
			group["members"] = input.rows[:129]
			for index, raw := range input.rows[:129] {
				raw.(map[string]any)["statementCompletion"] = fmt.Sprintf("%03d remains explicit.", index)
			}
			last := maps.Clone(groupTemplate)
			last["groupId"], last["members"] = "RGRP-UNICODE", input.rows[129:]
			source["groups"] = []any{group, last}
		}
		source["specPackagePath"] = "docs/specs/" + input.id
		admitted, err := requirementsourceadmission.Evaluate(source)
		if err != nil || admitted.ExitCode != 0 {
			return nil, fmt.Errorf("lookup fixture requirement source is invalid")
		}
		value, err := requirementsourceadmission.SourceValue(admitted.Source)
		if err != nil {
			return nil, err
		}
		requirementSources = append(requirementSources, value)
		record := map[string]any{"currentDigest": digest.SHA256TextRef("source-" + input.id), "kind": "requirement_source", "nodeId": input.node, "path": "docs/specs/" + input.id + "/requirements.v2.json", "sourceRef": source["sourceId"], "sourceRole": "requirements"}
		sources = append(sources, record)
		identity := maps.Clone(record)
		identity["expectedDigest"] = ""
		identitySources = append(identitySources, identity)
	}
	projections["requirementSources"] = requirementSources
	ref := func(id, role, source string) map[string]any {
		return map[string]any{"sourceRefId": id, "sourceRefKind": "source_id", "sourceRole": role, "sourceId": source}
	}
	node := func(id, label, kind string, order int, refs []any) map[string]any {
		return map[string]any{"nodeId": id, "label": label, "nodeKind": kind, "displayOrder": json.Number(fmt.Sprint(order)), "callerAnnotations": []any{}, "sourceRefs": refs}
	}
	tree := projections["specTree"].(map[string]any)
	nodes := []any{
		node("spec.root", "Workspace root", "meta_spec", 50, []any{ref("root.requirements", "requirements", "consumer.a")}),
		node("spec.child", "Child contracts", "module_spec", 10, []any{ref("child.requirements", "requirements", "consumer.b"), ref("child.overview", "overview", "consumer.a")}),
		node("spec.grandchild", "Nested contracts", "submodule_spec", 90, []any{ref("grandchild.requirements", "requirements", "consumer.c"), ref("grandchild.overview", "overview", "consumer.b")}),
	}
	edges := []any{map[string]any{"parentNodeId": "spec.root", "childNodeId": "spec.child"}, map[string]any{"parentNodeId": "spec.child", "childNodeId": "spec.grandchild"}}
	for index := range siblingCount {
		id := fmt.Sprintf("spec.sibling.%03d", index)
		nodes = append(nodes, node(id, fmt.Sprintf("Sibling %03d", index), "module_spec", 100+index, []any{ref(id+".overview", "overview", "consumer.a")}))
		edges = append(edges, map[string]any{"parentNodeId": "spec.root", "childNodeId": id})
	}
	parent := "spec.grandchild"
	for depth := range 6 {
		for index := range 64 {
			id := fmt.Sprintf("spec.depth.%d.%03d", depth+1, index)
			label := fmt.Sprintf("Level %d sibling %03d", depth+1, index)
			if index == 0 {
				label = fmt.Sprintf("Depth %d", depth+1)
			}
			nodes = append(nodes, node(id, label, "submodule_spec", index+1, []any{ref(id+".overview", "overview", "consumer.a")}))
			edges = append(edges, map[string]any{"parentNodeId": parent, "childNodeId": id})
		}
		parent = fmt.Sprintf("spec.depth.%d.000", depth+1)
	}
	tree["nodes"], tree["edges"] = nodes, edges
	admittedTree, err := requirementspectree.Evaluate(tree)
	if err != nil || admittedTree.ExitCode != 0 {
		return nil, fmt.Errorf("lookup fixture specification tree is invalid")
	}
	projections["specTree"] = requirementspectree.TreeValue(admittedTree.Tree)
	treeSource := map[string]any{"currentDigest": digest.SHA256TextRef("lookup-tree"), "kind": "spec_tree", "path": "proofkit/browser-fixture-tree.json", "sourceRef": "spec_tree:browser.fixture.tree"}
	sources = append(sources, treeSource)
	identityTree := maps.Clone(treeSource)
	identityTree["expectedDigest"] = ""
	identitySources = append(identitySources, identityTree)
	contextValue["sources"] = sources
	encoded, err := stablejson.Marshal(map[string]any{"catalogId": contextValue["catalogId"], "projections": projections, "sources": identitySources})
	if err != nil {
		return nil, err
	}
	contextValue["snapshotId"] = digest.SHA256TextRef(string(encoded))
	return map[string]any{"schemaVersion": json.Number("3"), "workspaceId": "browser.fixture.workspace", "context": contextValue}, nil
}
