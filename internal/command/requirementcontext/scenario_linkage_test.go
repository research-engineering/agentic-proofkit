package requirementcontext

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/projectfixture"
)

func TestContextCompositionChecksSourceQualifiedScenarioMembership(t *testing.T) {
	fixture := projectfixture.New(t)
	project := fixture.Project
	sources := project["requirementSources"].([]any)
	refs := make([]requirementspectree.SourceRef, 0, len(sources))
	for _, raw := range sources {
		id := raw.(map[string]any)["sourceId"].(string)
		refs = append(refs, requirementspectree.SourceRef{
			SourceRefID: id, SourceRefKind: "source_id", SourceRole: "requirements", SourceID: id,
		})
	}
	tree := requirementspectree.Tree{
		TreeID: "scenario.membership.collection", RootNodeID: "project.root",
		Nodes: []requirementspectree.Node{{
			NodeID: "project.root", NodeKind: "meta_spec", Label: "Scenario membership", DisplayOrder: 1, SourceRefs: refs,
		}},
	}
	projections := map[string]any{
		"specTree":           requirementspectree.TreeValue(tree),
		"requirementSources": sources,
		"proofBinding":       project["proofBinding"],
	}
	check := func() error {
		tree, admittedSources, binding, coverage, _, err := admitSnapshotProjections(projections)
		if err != nil {
			return err
		}
		inventory := []Source{{Kind: "spec_tree", SourceRef: "spec_tree:" + tree.TreeID}}
		for _, source := range admittedSources {
			inventory = append(inventory, Source{Kind: "requirement_source", SourceRef: source.SourceID(), NodeID: "project.root", SourceRole: "requirements"})
		}
		inventory = append(inventory, Source{Kind: "proof_binding", SourceRef: "proof_binding:" + binding.BindingID})
		return validateProjectionSources(tree, admittedSources, binding, coverage, inventory)
	}
	if err := check(); err != nil {
		t.Fatalf("reference-only baseline rejected: %v", err)
	}
	proofRequirement := project["proofBinding"].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	for _, mismatch := range []struct{ field, value string }{
		{"ownerId", "another.owner"},
		{"claimLevel", "advisory"},
		{"specPath", "docs/specs/other/requirements.v2.json"},
	} {
		original := proofRequirement[mismatch.field]
		proofRequirement[mismatch.field] = mismatch.value
		if err := check(); err == nil || !strings.Contains(err.Error(), "source-owned requirement fields") {
			t.Fatalf("%s mismatch admitted: %v", mismatch.field, err)
		}
		proofRequirement[mismatch.field] = original
	}
	second := sources[1].(map[string]any)
	scenario := map[string]any{
		"scenarioId": "collection.scenario.002", "requirementIds": []any{"REQ-WIRE-002"},
		"parameters": []any{}, "preconditions": []any{"A request is admitted."},
		"actionSequence":        []any{"Run the declared route."},
		"expectedObservations":  []any{"The response is accepted."},
		"forbiddenObservations": []any{}, "examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}
	second["scenarios"] = []any{scenario}
	if err := check(); err != nil {
		t.Fatalf("declared scenario for its member rejected: %v", err)
	}
	bindings := project["proofBinding"].(map[string]any)["bindings"].([]any)
	bindings[2].(map[string]any)["scenarioId"] = "collection.scenario.002"
	if err := check(); err == nil {
		t.Fatal("binding attached a declared scenario to a non-member requirement")
	}
	scenario["requirementIds"] = []any{"REQ-WIRE-002", "REQ-WIRE-003"}
	if err := check(); err != nil {
		t.Fatalf("declared many-to-many scenario membership rejected: %v", err)
	}
}
