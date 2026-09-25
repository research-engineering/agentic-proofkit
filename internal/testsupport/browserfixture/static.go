package browserfixture

import "fmt"

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

func StaticProof() (map[string]any, error) {
	input, err := CoverageInput("structured")
	if err != nil {
		return nil, err
	}
	return input["requirementProofBinding"].(map[string]any), nil
}
