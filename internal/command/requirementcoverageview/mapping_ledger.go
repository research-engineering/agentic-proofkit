package requirementcoverageview

import "github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"

type coverageStateDescriptor struct {
	commandPriority            int
	commandState               string
	evidenceClass              string
	ownerInvariantAdmissible   bool
	ownerInvariantWarns        bool
	requirementAdmissible      bool
	requirementMappingComplete bool
	requirementPriority        int
	requirementState           string
}

var coverageStateDescriptors = []coverageStateDescriptor{
	{
		commandPriority:            0,
		commandState:               "command_declared_semantic_falsifier_route_present",
		evidenceClass:              testevidenceinventory.EvidenceClassDeclaredSemanticFalsifierRoute,
		ownerInvariantAdmissible:   true,
		requirementAdmissible:      true,
		requirementMappingComplete: true,
		requirementPriority:        0,
		requirementState:           "mapped_to_declared_semantic_falsifier_route",
	},
	{
		commandPriority:            1,
		commandState:               "command_owner_nonsemantic_evidence",
		evidenceClass:              testevidenceinventory.EvidenceClassDeclaredPropertyOrFuzzRoute,
		ownerInvariantAdmissible:   true,
		requirementAdmissible:      true,
		requirementMappingComplete: true,
		requirementPriority:        1,
		requirementState:           "mapped_to_declared_property_or_fuzz_route",
	},
	{
		commandPriority:            1,
		commandState:               "command_owner_nonsemantic_evidence",
		evidenceClass:              testevidenceinventory.EvidenceClassDeclaredContractAdmissionRoute,
		ownerInvariantAdmissible:   true,
		requirementAdmissible:      true,
		requirementMappingComplete: true,
		requirementPriority:        2,
		requirementState:           "mapped_to_declared_contract_admission_route",
	},
	{
		commandPriority:          1,
		commandState:             "command_owner_nonsemantic_evidence",
		evidenceClass:            "governance_or_release",
		ownerInvariantAdmissible: true,
		requirementAdmissible:    true,
		requirementPriority:      3,
		requirementState:         "mapped_to_declared_governance_or_release_route_nonproduct",
	},
	{
		commandPriority:          1,
		commandState:             "command_owner_nonsemantic_evidence",
		evidenceClass:            "benchmark",
		ownerInvariantAdmissible: true,
		ownerInvariantWarns:      true,
		requirementAdmissible:    true,
		requirementPriority:      4,
		requirementState:         "benchmark_advisory_missing_policy",
	},
	{
		commandPriority:          2,
		commandState:             "command_proof_route_candidate_only",
		evidenceClass:            testevidenceinventory.EvidenceClassProofRouteCandidate,
		ownerInvariantAdmissible: true,
		ownerInvariantWarns:      true,
		requirementAdmissible:    true,
		requirementPriority:      5,
		requirementState:         "proof_route_candidate_only",
	},
	{
		commandPriority:          3,
		commandState:             "command_route_only_nonclaim",
		evidenceClass:            "routing_smoke_nonclaim",
		ownerInvariantAdmissible: true,
		ownerInvariantWarns:      true,
		requirementAdmissible:    true,
		requirementPriority:      6,
		requirementState:         "route_only_nonclaim",
	},
	{
		commandPriority:          1,
		commandState:             "command_owner_nonsemantic_evidence",
		evidenceClass:            "helper_or_testkit",
		ownerInvariantAdmissible: true,
		ownerInvariantWarns:      true,
		requirementAdmissible:    true,
		requirementPriority:      7,
		requirementState:         "helper_or_testkit_nonclaim",
	},
	{
		evidenceClass:         "",
		requirementAdmissible: true,
		requirementState:      "deferred_with_owner",
	},
	{
		evidenceClass:         "",
		requirementAdmissible: true,
		requirementState:      "missing_proof_binding_route",
	},
	{
		evidenceClass:            "",
		ownerInvariantAdmissible: true,
		ownerInvariantWarns:      true,
		requirementAdmissible:    true,
		requirementState:         "missing_test_inventory",
	},
	{
		evidenceClass:         "",
		requirementAdmissible: true,
		requirementState:      "not_applicable",
	},
}

const missingCommandCoverageState = "missing_command_declared_semantic_falsifier_route"

func strongestMappingState(entries []testevidenceinventory.Entry) (string, string) {
	bestPriority := len(coverageStateDescriptors) + 1
	bestState := "missing_test_inventory"
	bestClass := ""
	for _, entry := range entries {
		for _, descriptor := range coverageStateDescriptors {
			if descriptor.evidenceClass == "" || descriptor.evidenceClass != entry.EvidenceClass || descriptor.requirementPriority >= bestPriority {
				continue
			}
			bestPriority = descriptor.requirementPriority
			bestState = descriptor.requirementState
			bestClass = descriptor.evidenceClass
		}
	}
	return bestState, bestClass
}

func commandState(entries []testevidenceinventory.Entry) string {
	bestPriority := len(coverageStateDescriptors) + 1
	bestState := missingCommandCoverageState
	for _, entry := range entries {
		for _, descriptor := range coverageStateDescriptors {
			if descriptor.commandState == "" || descriptor.evidenceClass != entry.EvidenceClass || descriptor.commandPriority >= bestPriority {
				continue
			}
			bestPriority = descriptor.commandPriority
			bestState = descriptor.commandState
		}
	}
	return bestState
}

func requirementCoverageStateDescriptor(state string) (coverageStateDescriptor, bool) {
	for _, descriptor := range coverageStateDescriptors {
		if descriptor.requirementAdmissible && descriptor.requirementState == state {
			return descriptor, true
		}
	}
	return coverageStateDescriptor{}, false
}

func ownerInvariantCoverageStateDescriptor(state string) (coverageStateDescriptor, bool) {
	for _, descriptor := range coverageStateDescriptors {
		if descriptor.ownerInvariantAdmissible && descriptor.requirementState == state {
			return descriptor, true
		}
	}
	return coverageStateDescriptor{}, false
}

func commandCoverageStateAllowed(state string) bool {
	if state == missingCommandCoverageState {
		return true
	}
	for _, descriptor := range coverageStateDescriptors {
		if descriptor.commandState == state {
			return true
		}
	}
	return false
}

func commandCoverageDiagnostics(commandID string, state string, completenessDeclaration string) ([]string, []string) {
	failures := []string{}
	warnings := []string{}
	diagnostic := state + ":" + commandID
	switch state {
	case missingCommandCoverageState:
		if completenessDeclaration == "selected_paths_advisory" {
			warnings = append(warnings, diagnostic)
		} else {
			failures = append(failures, diagnostic)
		}
	case "command_owner_nonsemantic_evidence":
		diagnostic = "nonsemantic_command_evidence:" + commandID
		if completenessDeclaration == "selected_paths_advisory" {
			warnings = append(warnings, diagnostic)
		} else {
			failures = append(failures, diagnostic)
		}
	case "command_route_only_nonclaim":
		warnings = append(warnings, diagnostic)
	case "command_proof_route_candidate_only":
		if completenessDeclaration == "selected_paths_advisory" {
			warnings = append(warnings, diagnostic)
		} else {
			failures = append(failures, diagnostic)
		}
	}
	return failures, warnings
}

func requirementCoverageStateComplete(state string) bool {
	descriptor, ok := requirementCoverageStateDescriptor(state)
	return ok && descriptor.requirementMappingComplete
}

func ownerInvariantCoverageStateWarns(state string) bool {
	descriptor, ok := ownerInvariantCoverageStateDescriptor(state)
	return !ok || descriptor.ownerInvariantWarns
}
