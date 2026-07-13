package app

import (
	"fmt"
	"slices"
)

type descriptorArguments struct {
	present map[string]bool
	values  map[string][]string
}

func classifyDescriptorArguments(descriptor commandDescriptor, args []string) descriptorArguments {
	parsed := descriptorArguments{present: map[string]bool{}, values: map[string][]string{}}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !slices.Contains(descriptor.allowedFlags, argument) {
			continue
		}
		parsed.present[argument] = true
		if flagRequiresValue(argument) {
			if index+1 < len(args) {
				parsed.values[argument] = append(parsed.values[argument], args[index+1])
				index++
			}
		}
	}
	return parsed
}

func validateFlagConstraints(descriptor commandDescriptor, parsed descriptorArguments) error {
	if descriptor.input == commandInputRequired && !parsed.present["--input"] {
		return fmt.Errorf("%s requires --input <path|->", descriptor.name)
	}
	for _, flag := range descriptor.requiredFlags {
		if !parsed.present[flag] {
			return fmt.Errorf("%s requires %s", descriptor.name, flag)
		}
	}
	for _, group := range descriptor.exactlyOneOfFlagGroups {
		count := 0
		for _, flag := range group {
			if parsed.present[flag] {
				count++
			}
		}
		if count != 1 {
			return fmt.Errorf("%s requires exactly one of %v", descriptor.name, group)
		}
	}
	for _, requirement := range descriptor.flagValueRequirements {
		if !slices.Contains(parsed.values[requirement.Flag], requirement.Value) {
			continue
		}
		for _, flag := range requirement.RequiredFlags {
			if !parsed.present[flag] {
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
