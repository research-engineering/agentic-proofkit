package main

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var cliFlagConditionAtomPattern = regexp.MustCompile(`^(--[a-z][a-z0-9-]*)=([a-z0-9][a-z0-9-]*)$`)

const cliFlagConditionModelDefinitionID = "proofkit.adoption-contract-envelope.output.v1.root-shape"
const cliFlagConditionModelCommand = "adoption-contract-envelope"
const cliFlagConditionModelDirection = "output"

type rootShapeConditionCase struct {
	Dimensions map[string]string
	Raw        string
	VariantID  string
}

func parseCLIFlagCondition(condition string) (map[string]string, error) {
	atoms := strings.Fields(condition)
	if len(atoms) == 0 {
		return nil, errors.New("cli_flag_conjunction_v1 condition must contain at least one atom")
	}
	if condition != strings.Join(atoms, " ") {
		return nil, errors.New("cli_flag_conjunction_v1 condition must use one ASCII space between atoms")
	}
	dimensions := make(map[string]string, len(atoms))
	previousFlag := ""
	for _, atom := range atoms {
		match := cliFlagConditionAtomPattern.FindStringSubmatch(atom)
		if match == nil {
			return nil, fmt.Errorf("invalid cli_flag_conjunction_v1 atom %q", atom)
		}
		flagName := match[1]
		if previousFlag != "" && previousFlag >= flagName {
			return nil, errors.New("cli_flag_conjunction_v1 atoms must be sorted by unique flag name")
		}
		previousFlag = flagName
		dimensions[flagName] = match[2]
	}
	return dimensions, nil
}

func admitCLIFlagConditionCases(id string, cases []rootShapeConditionCase) error {
	if len(cases) == 0 {
		return fmt.Errorf("contract definition %s cli_flag_conjunction_v1 requires condition cases", id)
	}
	expectedFlags := sortedKeys(cases[0].Dimensions)
	statesByFlag := make(map[string]map[string]struct{}, len(expectedFlags))
	for _, conditionCase := range cases {
		actualFlags := sortedKeys(conditionCase.Dimensions)
		if !slices.Equal(actualFlags, expectedFlags) {
			return fmt.Errorf(
				"contract definition %s cli_flag_conjunction_v1 condition %q dimensions=%v want %v",
				id,
				conditionCase.Raw,
				actualFlags,
				expectedFlags,
			)
		}
		for flagName, state := range conditionCase.Dimensions {
			if statesByFlag[flagName] == nil {
				statesByFlag[flagName] = map[string]struct{}{}
			}
			statesByFlag[flagName][state] = struct{}{}
		}
	}
	for _, flagName := range expectedFlags {
		states := statesByFlag[flagName]
		if _, hasPresent := states["present"]; hasPresent {
			for state := range states {
				if state != "absent" && state != "present" {
					return fmt.Errorf("contract definition %s cli_flag_conjunction_v1 flag %s mixes present with literal values", id, flagName)
				}
			}
		}
	}
	for leftIndex, left := range cases {
		for _, right := range cases[leftIndex+1:] {
			if left.VariantID == right.VariantID {
				continue
			}
			disjoint := false
			for _, flagName := range expectedFlags {
				if left.Dimensions[flagName] != right.Dimensions[flagName] {
					disjoint = true
					break
				}
			}
			if !disjoint {
				return fmt.Errorf(
					"contract definition %s cli_flag_conjunction_v1 conditions %q and %q overlap across variants %s and %s",
					id,
					left.Raw,
					right.Raw,
					left.VariantID,
					right.VariantID,
				)
			}
		}
	}
	return nil
}

func admitConditionModelFlags(command string, direction string, definitionID string, definition map[string]any, allowedFlags []string) error {
	shape := definition["fieldTree"].(map[string]any)
	if shape["conditionModel"] != "cli_flag_conjunction_v1" {
		return nil
	}
	context := command + " " + direction + "Contract"
	if command != cliFlagConditionModelCommand || direction != cliFlagConditionModelDirection || definitionID != cliFlagConditionModelDefinitionID {
		return fmt.Errorf("%s condition model definition %s is not bound to its admitted command and direction", context, definitionID)
	}
	variants := shape["variants"].([]any)
	firstVariant := variants[0].(map[string]any)
	firstCondition := firstVariant["when"].([]any)[0].(string)
	dimensions, err := parseCLIFlagCondition(firstCondition)
	if err != nil {
		return fmt.Errorf("%s condition model: %w", context, err)
	}
	for _, flagName := range sortedKeys(dimensions) {
		if !slices.Contains(allowedFlags, flagName) {
			return fmt.Errorf("%s condition model dimension %s is not an allowed flag", context, flagName)
		}
	}
	return nil
}
