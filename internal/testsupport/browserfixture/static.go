package browserfixture

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

// StaticSource exercises browserdoc through the admitted source renderer.
func StaticSource() (map[string]any, error) {
	source, err := Source()
	if err != nil {
		return nil, err
	}
	groups := []any{}
	for index, text := range []string{"\u039f\u0394\u039f\u03a3", "\u0130stanbul", "ASCII Needle", "Caf\u00e9", "Cafe\u0301"} {
		group := requirementSource(text, "high")["groups"].([]any)[0].(map[string]any)
		group["groupId"] = fmt.Sprintf("RGRP-STATIC-%d", index)
		member := group["members"].([]any)[0].(map[string]any)
		if index > 0 {
			member["requirementId"] = fmt.Sprintf("REQ-STATIC-%d", index)
			member["fields"].(map[string]any)["ownerId"] = "browser.fixture.other"
		}
		groups = append(groups, group)
	}
	source["groups"] = groups
	return source, nil
}

func StaticTree() (map[string]any, error) {
	workspace, err := Workspace()
	if err != nil {
		return nil, err
	}
	tree := workspace["context"].(map[string]any)["projections"].(map[string]any)["specTree"].(map[string]any)
	tree["nodes"].([]any)[0].(map[string]any)["label"] = "\u039f\u0394\u039f\u03a3 \u0130stanbul <input>"
	return tree, nil
}

func StaticFilterTree() (map[string]any, error) {
	tree, err := StaticTree()
	if err != nil {
		return nil, err
	}
	root := tree["nodes"].([]any)[0].(map[string]any)
	rootRef := root["sourceRefs"].([]any)[0].(map[string]any)
	contentDigest := digest.SHA256TextRef("Synthetic filter reference.")
	root["sourceRefs"] = append(root["sourceRefs"].([]any), map[string]any{
		"sourceRefId": "spec.root.overview", "sourceRole": "overview", "sourceRefKind": "path_digest",
		"sourcePath": "docs/specs/filter-fixture/overview.md", "recordedSourceDigest": contentDigest,
		"currentSourceDigest": contentDigest, "digestAlgorithm": "sha256",
	})
	tree["overlays"] = []any{
		map[string]any{"overlayId": "filter.source", "overlayKind": "source", "targetNodeId": "spec.root", "refKind": "source_ref", "refId": rootRef["sourceRefId"], "label": "Source overlay", "callerAnnotations": []any{}},
		map[string]any{"overlayId": "filter.rendered", "overlayKind": "rendered_view", "targetNodeId": "spec.root", "refKind": "rendered_artifact", "refId": "filter.view", "refPath": "artifacts/filter-view.html", "refDigest": contentDigest, "digestAlgorithm": "sha256", "label": "Rendered overlay", "callerAnnotations": []any{}},
	}
	tree["nodes"] = append(tree["nodes"].([]any), map[string]any{
		"nodeId": "spec.module", "nodeKind": "module_spec", "label": "Unrelated module", "displayOrder": json.Number("1"), "callerAnnotations": []any{},
		"sourceRefs": []any{map[string]any{"sourceRefId": "spec.module.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "filter.module.requirements"}},
	}, map[string]any{
		"nodeId": "spec.module.second", "nodeKind": "module_spec", "label": "Second module", "displayOrder": json.Number("2"), "callerAnnotations": []any{},
		"sourceRefs": []any{map[string]any{"sourceRefId": "spec.module.second.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "filter.module.second.requirements"}},
	})
	tree["edges"] = []any{
		map[string]any{"parentNodeId": "spec.root", "childNodeId": "spec.module"},
		map[string]any{"parentNodeId": "spec.root", "childNodeId": "spec.module.second"},
	}
	return tree, nil
}

func StaticProof() (map[string]any, error) {
	input, err := CoverageInput("structured")
	if err != nil {
		return nil, err
	}
	return input["requirementProofBinding"].(map[string]any), nil
}
