package app

import (
	"slices"
	"strings"
)

const maximumCommandRouteTokens = 4

var commandDescriptorByRoute = buildCommandDescriptorRouteIndex(commandDescriptors)

func buildCommandDescriptorRouteIndex(descriptors []commandDescriptor) map[string]commandDescriptor {
	index := make(map[string]commandDescriptor, len(descriptors))
	for descriptorIndex, descriptor := range descriptors {
		if !validCommandRoute(descriptor.routeTokens) {
			panic("invalid command route: " + descriptor.name)
		}
		for existingIndex := 0; existingIndex < descriptorIndex; existingIndex++ {
			existingDescriptor := descriptors[existingIndex]
			existing := existingDescriptor.routeTokens
			if slices.Equal(existing, descriptor.routeTokens) {
				panic("duplicate command route: " + commandRouteText(descriptor.routeTokens))
			}
			if commandRoutePrefix(existing, descriptor.routeTokens) || commandRoutePrefix(descriptor.routeTokens, existing) {
				panic("ambiguous command route prefix: " + existingDescriptor.name + " and " + descriptor.name)
			}
		}
		index[commandRouteKey(descriptor.routeTokens)] = descriptor.clone()
	}
	return index
}

func commandDescriptorForRoute(args []string) (commandDescriptor, int, bool) {
	maximum := len(args)
	if maximum > maximumCommandRouteTokens {
		maximum = maximumCommandRouteTokens
	}
	for consumed := maximum; consumed >= 1; consumed-- {
		descriptor, ok := commandDescriptorByRoute[commandRouteKey(args[:consumed])]
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
	if len(route) == 0 || len(route) > maximumCommandRouteTokens {
		return false
	}
	for _, token := range route {
		if !validCommandRouteToken(token) {
			return false
		}
	}
	return true
}

func validCommandRouteToken(token string) bool {
	if token == "" || token[0] == '-' || token[len(token)-1] == '-' {
		return false
	}
	previousHyphen := false
	for _, value := range token {
		if value == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		previousHyphen = false
		if value < 'a' || value > 'z' {
			if value < '0' || value > '9' {
				return false
			}
		}
	}
	return true
}

func commandRoutePrefix(prefix, value []string) bool {
	return len(prefix) < len(value) && slices.Equal(prefix, value[:len(prefix)])
}

func commandRouteKey(route []string) string {
	return strings.Join(route, "\x00")
}

func commandRouteText(route []string) string {
	return strings.Join(route, " ")
}
