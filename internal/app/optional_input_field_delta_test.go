package app

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func publicABIDefinitionDigest(record map[string]any) (string, error) {
	value := clonePublicABIRecord(record)
	delete(value, "canonicalDigest")
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		return "", err
	}
	return digest.SHA256BytesRef(bytes.TrimSuffix(encoded, []byte{'\n'})), nil
}

// Adding exactly the removed required field must reconstruct the immutable old
// definition. All other fields and original record order remain observable.
func normalizeOptionalInputFieldPublicABIDelta(current map[string]any, commandName, field, predecessorDigest string) error {
	commands, _, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	command, ok := commands[commandName]
	if !ok {
		return fmt.Errorf("optional-field correction command is missing")
	}
	input, ok := command["inputContract"].(map[string]any)
	if !ok {
		return fmt.Errorf("optional-field correction input contract is missing")
	}
	definitionID, ok := input["rootDefinitionRef"].(string)
	if !ok {
		return fmt.Errorf("optional-field correction definition reference is missing")
	}
	definitions, _, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		return err
	}
	definition, ok := definitions[definitionID]
	if !ok {
		return fmt.Errorf("optional-field correction definition is missing")
	}
	actual, err := publicABIDefinitionDigest(definition)
	if err != nil || definition["canonicalDigest"] != actual || input["rootDefinitionDigest"] != actual || actual == predecessorDigest {
		return fmt.Errorf("optional-field correction has stale or unbound definition content")
	}
	tree, ok := definition["fieldTree"].(map[string]any)
	if !ok {
		return fmt.Errorf("optional-field correction field tree is invalid")
	}
	variants, ok := tree["variants"].([]any)
	if !ok || len(variants) != 1 {
		return fmt.Errorf("optional-field correction variants differ")
	}
	variant, ok := variants[0].(map[string]any)
	if !ok {
		return fmt.Errorf("optional-field correction variant is invalid")
	}
	allowed, aOK := variant["allowedFields"].([]any)
	required, rOK := variant["requiredFields"].([]any)
	if !aOK || !rOK {
		return fmt.Errorf("optional-field correction field sets are invalid")
	}
	for _, values := range [][]any{allowed, required} {
		previous := ""
		for _, raw := range values {
			text, ok := raw.(string)
			if !ok || text == "" || previous >= text {
				return fmt.Errorf("optional-field correction field sets are not canonical")
			}
			previous = text
		}
	}
	if !slices.Contains(allowed, any(field)) || slices.Contains(required, any(field)) {
		return fmt.Errorf("optional-field correction does not preserve the field as optional")
	}
	restoredFields := append(slices.Clone(required), field)
	slices.SortFunc(restoredFields, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	variant, tree, definition = clonePublicABIRecord(variant), clonePublicABIRecord(tree), clonePublicABIRecord(definition)
	variant["requiredFields"] = restoredFields
	tree["variants"] = []any{variant}
	definition["fieldTree"] = tree
	if restored, err := publicABIDefinitionDigest(definition); err != nil || restored != predecessorDigest {
		return fmt.Errorf("optional-field correction changes other root fields")
	}
	definition["canonicalDigest"] = predecessorDigest
	input, command = clonePublicABIRecord(input), clonePublicABIRecord(command)
	input["rootDefinitionDigest"] = predecessorDigest
	command["inputContract"] = input
	definitionValues := slices.Clone(current["contractDefinitions"].([]any))
	for index, raw := range definitionValues {
		if raw.(map[string]any)["definitionId"] == definitionID {
			definitionValues[index] = definition
		}
	}
	commandValues := slices.Clone(current["commands"].([]any))
	for index, raw := range commandValues {
		if raw.(map[string]any)["command"] == commandName {
			commandValues[index] = command
		}
	}
	current["contractDefinitions"], current["commands"] = definitionValues, commandValues
	return nil
}
