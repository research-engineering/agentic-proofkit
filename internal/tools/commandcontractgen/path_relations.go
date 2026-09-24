package main

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/specoverviewclaims"
)

func expectedPathRelations(command, direction string) ([]any, string) {
	if command == "spec-overview-claims" && direction == "input" {
		return []any{specoverviewclaims.InputPathRelation()}, "proofkit.spec-overview-claims.input.v2"
	}
	return nil, ""
}

func admitPathRelations(command, direction string, contract map[string]any, root definitionRecord) error {
	expected, expectedContractID := expectedPathRelations(command, direction)
	actual, present := contract["pathRelations"]
	if len(expected) == 0 {
		if present {
			return fmt.Errorf("%s %s has unowned path relations", command, direction)
		}
		return nil
	}
	if contract["contractId"] != expectedContractID || !present || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("%s %s path relation differs from its native owner", command, direction)
	}
	variants := root.Content["fieldTree"].(map[string]any)["variants"].([]any)
	for _, raw := range expected {
		relation := raw.(map[string]any)
		for _, field := range []string{relation["sourceField"].(string), relation["targetField"].(string)} {
			found := false
			for _, variant := range variants {
				if slices.Contains(variant.(map[string]any)["allowedFields"].([]any), any(field)) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%s %s path relation root field is absent", command, direction)
			}
		}
	}
	return nil
}
