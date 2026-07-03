package app

import "strings"

var agentEnvelopeCommands = commandNamesMatching(func(descriptor commandDescriptor) bool {
	return descriptor.agentEnvelope
})

var contractEnvelopeCommands = commandNamesMatching(func(descriptor commandDescriptor) bool {
	return descriptor.contractEnvelope
})

func agentEnvelopeCommandList() string {
	return strings.Join(agentEnvelopeCommands, ", ")
}

func contractEnvelopeCommandList() string {
	return strings.Join(contractEnvelopeCommands, ", ")
}
