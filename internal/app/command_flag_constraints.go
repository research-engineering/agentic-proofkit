package app

import (
	"fmt"
	"slices"
)

func validateFlagConstraints(descriptor commandDescriptor, args []string) error {
	present := map[string]bool{}
	values := map[string][]string{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !slices.Contains(descriptor.allowedFlags, argument) {
			continue
		}
		present[argument] = true
		if flagRequiresValue(argument) {
			if index+1 < len(args) && !slices.Contains(descriptor.allowedFlags, args[index+1]) {
				values[argument] = append(values[argument], args[index+1])
				index++
			}
		}
	}
	if descriptor.input == commandInputRequired && !present["--input"] {
		return fmt.Errorf("%s requires --input <path|->", descriptor.name)
	}
	for _, flag := range descriptor.requiredFlags {
		if !present[flag] {
			return fmt.Errorf("%s requires %s", descriptor.name, flag)
		}
	}
	for _, group := range descriptor.exactlyOneOfFlagGroups {
		count := 0
		for _, flag := range group {
			if present[flag] {
				count++
			}
		}
		if count != 1 {
			return fmt.Errorf("%s requires exactly one of %v", descriptor.name, group)
		}
	}
	for _, requirement := range descriptor.flagValueRequirements {
		if !slices.Contains(values[requirement.Flag], requirement.Value) {
			continue
		}
		for _, flag := range requirement.RequiredFlags {
			if !present[flag] {
				return fmt.Errorf("%s %s %s requires %s", descriptor.name, requirement.Flag, requirement.Value, flag)
			}
		}
	}
	return nil
}

func flagRequiresValue(flag string) bool {
	switch flag {
	case "--agent-envelope", "--contract-envelope", "--empty-local-environment-policy", "--help", "-h", "--list", "--materialization-manifest", "--normalized-inventory", "--open", "--serve", "--stack-diverse", "--verify":
		return false
	default:
		return true
	}
}
