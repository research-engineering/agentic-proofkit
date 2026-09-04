package app

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
)

var commandDescriptorByRoute = buildCommandDescriptorRouteIndex(commandDescriptors)

func buildCommandDescriptorRouteIndex(descriptors []commandDescriptor) map[string]commandDescriptor {
	index := make(map[string]commandDescriptor, len(descriptors))
	for descriptorIndex, descriptor := range descriptors {
		if !commandroute.Valid(descriptor.routeTokens) {
			panic("invalid command route: " + descriptor.name)
		}
		for existingIndex := 0; existingIndex < descriptorIndex; existingIndex++ {
			existingDescriptor := descriptors[existingIndex]
			existing := existingDescriptor.routeTokens
			if slices.Equal(existing, descriptor.routeTokens) {
				panic("duplicate command route: " + commandroute.Text(descriptor.routeTokens))
			}
			if commandroute.Prefix(existing, descriptor.routeTokens) || commandroute.Prefix(descriptor.routeTokens, existing) {
				panic("ambiguous command route prefix: " + existingDescriptor.name + " and " + descriptor.name)
			}
		}
		index[commandroute.Key(descriptor.routeTokens)] = descriptor.clone()
	}
	return index
}

func commandDescriptorForRoute(args []string) (commandDescriptor, int, bool) {
	maximum := len(args)
	if maximum > commandroute.MaximumTokens {
		maximum = commandroute.MaximumTokens
	}
	for consumed := maximum; consumed >= 1; consumed-- {
		descriptor, ok := commandDescriptorByRoute[commandroute.Key(args[:consumed])]
		if ok {
			return descriptor.clone(), consumed, true
		}
	}
	return commandDescriptor{}, 0, false
}

func commandDescriptorForHelpTarget(tokens []string) (commandDescriptor, bool) {
	if descriptor, consumed, ok := commandDescriptorForRoute(tokens); ok && consumed == len(tokens) {
		return descriptor, true
	}
	return commandDescriptor{}, false
}

func validCommandRoute(route []string) bool {
	return commandroute.Valid(route)
}

func commandRouteText(route []string) string {
	return commandroute.Text(route)
}
