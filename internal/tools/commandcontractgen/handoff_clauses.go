package main

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
)

func expectedHandoffClauses(command, direction string) []any {
	if direction == "output" && (command == "requirement-browser-server" || command == "view") {
		return requirementbrowser.OutputHandoffClauses()
	}
	return nil
}

func admitHandoffClauses(command, direction string, contract map[string]any, root definitionRecord) error {
	expected := expectedHandoffClauses(command, direction)
	actual, present := contract["handoffClauses"]
	if len(expected) == 0 {
		if present {
			return fmt.Errorf("%s %s has unowned handoff clauses", command, direction)
		}
		return nil
	}
	if !present || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("%s %s handoff clauses differ from browser owner", command, direction)
	}
	clause := expected[0].(map[string]any)
	variantID := clause["appliesWhen"]
	for _, raw := range root.Content["fieldTree"].(map[string]any)["variants"].([]any) {
		variant := raw.(map[string]any)
		if variant["variantId"] == variantID && slices.Contains(variant["allowedFields"].([]any), any("annotations")) {
			return nil
		}
	}
	return fmt.Errorf("%s %s handoff variant has no annotations", command, direction)
}

func refreshHandoffClauses(command string, contract map[string]any) error {
	contract["handoffClauses"] = expectedHandoffClauses(command, "output")
	if command != "view" {
		return nil
	}
	contract["contractId"] = "proofkit.view.output.v2"
	summary, ok := contract["compatibilitySummary"].([]any)
	if !ok {
		return fmt.Errorf("view output has no compatibility summary")
	}
	updated := false
	for index, raw := range summary {
		line, ok := raw.(string)
		if ok && strings.HasPrefix(line, "One closed captured project supplies context schemaVersion=") {
			summary[index] = fmt.Sprintf("One closed captured project supplies context schemaVersion=%d, exact source-role references and source nonClaims; retired workspace context versions are rejected.", requirementcontext.SnapshotSchemaVersion)
			updated = true
		}
	}
	if !updated {
		return fmt.Errorf("view output context compatibility claim is absent")
	}
	contract["compatibilitySummary"] = summary
	return nil
}
