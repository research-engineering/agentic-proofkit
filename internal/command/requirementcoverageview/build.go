package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"sort"
)

func build(raw any) (map[string]any, error) {
	input, err := admitCompositeInput(raw)
	if err != nil {
		return nil, err
	}
	failures := []string{}
	warnings := []string{}
	ownerSet := mapSet(input.CoverageUniverse.OwnerIDs)
	failures = append(failures, ownerScopeFailures(input, ownerSet)...)
	knownRequirementIDs := mapSet(scopedSourceRequirementIDs(input.Source, ownerSet))
	knownCommandIDs := mapSet(scopedProofCommandIDs(input, ownerSet))
	for _, commandID := range input.CoverageUniverse.CommandRefs {
		knownCommandIDs[commandID] = struct{}{}
	}
	knownWitnessRefs := mapSet(scopedProofWitnessRefs(input, ownerSet))
	knownOwnerInvariantIDs := map[string]struct{}{}
	for _, invariant := range input.OwnerInvariantRegistry.Invariants {
		if inOwnerScope(invariant.OwnerID, ownerSet) {
			knownOwnerInvariantIDs[invariant.OwnerInvariantID] = struct{}{}
		}
	}
	entries := []testevidenceinventory.Entry{}
	if input.Inventory == nil {
		warnings = append(warnings, "missing_test_inventory:input")
	} else {
		if input.Inventory.Report.State != "passed" {
			failures = append(failures, "test_inventory_failed:"+input.Inventory.Inventory.InventoryID)
		}
		entries = input.Inventory.Inventory.Entries
		failures = append(failures, unknownInventoryRefs(entries, knownRequirementIDs, knownOwnerInvariantIDs, knownCommandIDs, knownWitnessRefs)...)
	}
	requirements := buildRequirementCoverage(input, entries, input.Inventory, &failures, &warnings)
	ownerInvariantCoverage := buildOwnerInvariantCoverage(input, entries, input.Inventory, &warnings)
	commandCoverage := buildCommandCoverage(input, entries, &failures, &warnings)
	deadZones := buildDeadZones(input, entries)
	if input.CoverageUniverse.CompletenessDeclaration == "selected_paths_advisory" {
		warnings = append(warnings, deadZoneDiagnostics("dead_zone_advisory", deadZones)...)
	} else {
		failures = append(failures, deadZoneDiagnostics("dead_zone", deadZones)...)
	}
	failures = sortedUnique(failures)
	warnings = sortedUnique(warnings)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append([]string{}, defaultNonClaims...)
	nonClaims = append(nonClaims, input.CoverageUniverse.NonClaims...)
	nonClaims = append(nonClaims, input.Source.NonClaims...)
	if input.Inventory != nil {
		nonClaims = append(nonClaims, anyStrings(input.Inventory.Report.NonClaims)...)
	}
	return map[string]any{
		"authority":                   "lookup_only",
		"bindingId":                   input.Proof.BindingID,
		"commandCoverage":             mapsToAny(commandCoverage),
		"commandCoverageCount":        len(commandCoverage),
		"completenessDeclaration":     input.CoverageUniverse.CompletenessDeclaration,
		"contractId":                  input.Proof.ContractID,
		"coverageUniverseId":          input.CoverageUniverse.UniverseID,
		"deadZones":                   mapsToAny(deadZones),
		"failureClassifications":      mapsToAny(diagnosticClassifications(failures, "failure")),
		"failureCount":                len(failures),
		"failures":                    admit.StringSliceToAny(failures),
		"guidanceSummary":             guidanceSummary(state, failures, warnings),
		"nonClaims":                   admit.StringSliceToAny(sortedUnique(nonClaims)),
		"ownerInvariantCoverage":      mapsToAny(ownerInvariantCoverage),
		"ownerInvariantCoverageCount": len(ownerInvariantCoverage),
		"ownerInvariantRegistryId":    input.OwnerInvariantRegistry.RegistryID,
		"proofMode":                   input.Proof.Mode,
		"requirementCoverage":         mapsToAny(requirements),
		"requirementCoverageCount":    len(requirements),
		"schemaVersion":               1,
		"sourceId":                    input.Source.SourceID,
		"state":                       state,
		"testInventoryId":             inventoryID(input.Inventory),
		"viewInputId":                 input.ViewInputID,
		"viewKind":                    "proofkit.requirement-coverage-view",
		"warningClassifications":      mapsToAny(diagnosticClassifications(warnings, "warning")),
		"warningCount":                len(warnings),
		"warnings":                    admit.StringSliceToAny(warnings),
	}, nil
}

func buildOwnerInvariantCoverage(input compositeInput, entries []testevidenceinventory.Entry, inventory *testevidenceinventory.Result, warnings *[]string) []map[string]any {
	ownerSet := mapSet(input.CoverageUniverse.OwnerIDs)
	invariants := make([]ownerInvariant, 0, len(input.OwnerInvariantRegistry.Invariants))
	for _, invariant := range input.OwnerInvariantRegistry.Invariants {
		if inOwnerScope(invariant.OwnerID, ownerSet) {
			invariants = append(invariants, invariant)
		}
	}
	sort.Slice(invariants, func(left, right int) bool {
		return invariants[left].OwnerInvariantID < invariants[right].OwnerInvariantID
	})
	result := make([]map[string]any, 0, len(invariants))
	for _, invariant := range invariants {
		matches := entriesReferencingOwnerInvariant(entries, invariant.OwnerInvariantID)
		state := "missing_test_inventory"
		evidenceClass := ""
		if inventory != nil && inventory.Report.State == "passed" {
			state, evidenceClass = strongestEntryState(matches)
		}
		invariantWarnings := []string{}
		if state == "missing_test_inventory" || state == "proof_route_candidate_only" || state == "route_only_nonclaim" || state == "helper_or_testkit_nonclaim" || state == "benchmark_advisory_missing_policy" {
			warning := "missing_owner_invariant_inventory:" + invariant.OwnerInvariantID
			invariantWarnings = append(invariantWarnings, warning)
			*warnings = append(*warnings, warning)
		}
		result = append(result, map[string]any{
			"coverageState":    state,
			"evidenceClass":    evidenceClass,
			"nonClaims":        admit.StringSliceToAny(invariant.NonClaims),
			"ownerId":          invariant.OwnerID,
			"ownerInvariantId": invariant.OwnerInvariantID,
			"sourcePath":       invariant.SourcePath,
			"summary":          invariant.Summary,
			"testIds":          admit.StringSliceToAny(entryIDs(matches)),
			"tests":            testEntriesToAny(matches),
			"warnings":         admit.StringSliceToAny(invariantWarnings),
		})
	}
	return result
}
func buildRequirementCoverage(input compositeInput, entries []testevidenceinventory.Entry, inventory *testevidenceinventory.Result, failures *[]string, warnings *[]string) []map[string]any {
	ownerSet := mapSet(input.CoverageUniverse.OwnerIDs)
	sourceRequirements := scopedSourceRequirements(input.Source, ownerSet)
	sort.Slice(sourceRequirements, func(left, right int) bool {
		return sourceRequirements[left].RequirementID < sourceRequirements[right].RequirementID
	})
	result := make([]map[string]any, 0, len(sourceRequirements))
	for _, requirement := range sourceRequirements {
		proof, hasProof := input.Proof.Requirements[requirement.RequirementID]
		entriesForRequirement := entriesReferencingRequirement(entries, requirement.RequirementID)
		commandIDs := proof.CommandIDs
		if hasProof && input.Proof.Mode == "compact" && len(commandIDs) == 0 {
			commandIDs = entryCommandRefs(entriesForRequirement)
		}
		scenarios := proof.Scenarios
		state, evidenceClass := requirementState(requirement, entriesForRequirement, inventory, hasProof)
		requirementFailures := []string{}
		if !hasProof && requirement.ClaimLevel == "blocking" && requirement.Lifecycle.State == "active" {
			requirementFailures = append(requirementFailures, "missing_proof_binding_route:"+requirement.RequirementID)
		}
		if requirementBlocks(requirement, state, input.CoverageUniverse.CompletenessDeclaration) {
			requirementFailures = append(requirementFailures, state+":"+requirement.RequirementID)
		}
		if requirementWarns(requirement, state, input.CoverageUniverse.CompletenessDeclaration) {
			*warnings = append(*warnings, state+":"+requirement.RequirementID)
		}
		*failures = append(*failures, requirementFailures...)
		result = append(result, map[string]any{
			"claimLevel":         requirement.ClaimLevel,
			"commandIds":         admit.StringSliceToAny(commandIDs),
			"coverageState":      state,
			"evidenceClass":      evidenceClass,
			"environmentClasses": admit.StringSliceToAny(proof.EnvironmentClasses),
			"failures":           admit.StringSliceToAny(requirementFailures),
			"invariant":          requirement.Invariant,
			"lifecycleState":     requirement.Lifecycle.State,
			"nonClaims":          admit.StringSliceToAny(requirement.NonClaims),
			"ownerId":            requirement.OwnerID,
			"proofState":         proof.ProofState,
			"requirementId":      requirement.RequirementID,
			"scenarioCount":      len(scenarios),
			"scenarios":          scenariosToAny(scenarios),
			"specPath":           input.Source.RequirementsPath,
			"testIds":            admit.StringSliceToAny(entryIDs(entriesForRequirement)),
			"tests":              testEntriesToAny(entriesForRequirement),
			"verifyCommands":     admit.StringSliceToAny(proof.VerifyCommands),
			"witnessRefs":        admit.StringSliceToAny(proof.WitnessRefs),
			"witnessSelectors":   admit.StringSliceToAny(proof.WitnessSelectors),
		})
	}
	for requirementID := range input.Proof.Requirements {
		requirement, ok := sourceRequirementByID(input.Source, requirementID)
		if !ok {
			*failures = append(*failures, "proof_binding_unknown_requirement:"+requirementID)
			continue
		}
		if !inOwnerScope(requirement.OwnerID, ownerSet) {
			continue
		}
	}
	return result
}
func buildCommandCoverage(input compositeInput, entries []testevidenceinventory.Entry, failures *[]string, warnings *[]string) []map[string]any {
	ownerSet := mapSet(input.CoverageUniverse.OwnerIDs)
	commands := sortedUnique(append(scopedProofCommandIDs(input, ownerSet), input.CoverageUniverse.CommandRefs...))
	result := make([]map[string]any, 0, len(commands))
	for _, commandID := range commands {
		matches := entriesReferencingCommand(entries, commandID)
		state := commandState(matches)
		commandFailures := []string{}
		if state == "missing_command_semantic_falsifier" && input.CoverageUniverse.CompletenessDeclaration != "selected_paths_advisory" {
			commandFailures = append(commandFailures, state+":"+commandID)
			*failures = append(*failures, commandFailures...)
		}
		if state == "command_owner_nonsemantic_evidence" && input.CoverageUniverse.CompletenessDeclaration != "selected_paths_advisory" {
			commandFailures = append(commandFailures, "nonsemantic_command_evidence:"+commandID)
			*failures = append(*failures, commandFailures...)
		}
		if state == "missing_command_semantic_falsifier" && input.CoverageUniverse.CompletenessDeclaration == "selected_paths_advisory" {
			*warnings = append(*warnings, state+":"+commandID)
		}
		if state == "command_owner_nonsemantic_evidence" && input.CoverageUniverse.CompletenessDeclaration == "selected_paths_advisory" {
			*warnings = append(*warnings, "nonsemantic_command_evidence:"+commandID)
		}
		if state == "command_route_only_nonclaim" {
			*warnings = append(*warnings, state+":"+commandID)
		}
		if state == "command_proof_route_candidate_only" {
			diagnostic := state + ":" + commandID
			if input.CoverageUniverse.CompletenessDeclaration == "selected_paths_advisory" {
				*warnings = append(*warnings, diagnostic)
			} else {
				commandFailures = append(commandFailures, diagnostic)
				*failures = append(*failures, diagnostic)
			}
		}
		result = append(result, map[string]any{
			"commandId":     commandID,
			"coverageState": state,
			"failures":      admit.StringSliceToAny(commandFailures),
			"testIds":       admit.StringSliceToAny(entryIDs(matches)),
		})
	}
	return result
}
func buildDeadZones(input compositeInput, entries []testevidenceinventory.Entry) []map[string]any {
	ownerSet := mapSet(input.CoverageUniverse.OwnerIDs)
	requirementOwners := map[string]struct{}{}
	for _, requirement := range scopedSourceRequirements(input.Source, ownerSet) {
		requirementOwners[requirement.OwnerID] = struct{}{}
	}
	testPaths := map[string]struct{}{}
	for _, entry := range entries {
		testPaths[entry.SourcePath] = struct{}{}
	}
	deadZones := []map[string]any{}
	for _, item := range input.CoverageUniverse.CodeSurfaces {
		if _, ok := requirementOwners[item.OwnerID]; !ok {
			deadZones = append(deadZones, deadZone("unbound_code_surface", item))
		}
	}
	for _, item := range input.CoverageUniverse.SpecSurfaces {
		if _, ok := requirementOwners[item.OwnerID]; !ok {
			deadZones = append(deadZones, deadZone("unbound_spec_surface", item))
		}
	}
	for _, item := range input.CoverageUniverse.TestSurfaces {
		if _, ok := testPaths[item.Path]; !ok {
			deadZones = append(deadZones, deadZone("unbound_test_surface", item))
		}
	}
	sort.Slice(deadZones, func(left, right int) bool {
		return stringValue(deadZones[left]["surfaceId"]) < stringValue(deadZones[right]["surfaceId"])
	})
	return deadZones
}
func deadZone(kind string, item surface) map[string]any {
	return map[string]any{"deadZoneKind": kind, "ownerId": item.OwnerID, "path": item.Path, "surfaceId": item.SurfaceID}
}

func deadZoneDiagnostics(prefix string, deadZones []map[string]any) []string {
	out := make([]string, 0, len(deadZones))
	for _, item := range deadZones {
		out = append(out, prefix+":"+stringValue(item["deadZoneKind"])+":"+stringValue(item["surfaceId"]))
	}
	sort.Strings(out)
	return out
}

func ownerScopeFailures(input compositeInput, ownerSet map[string]struct{}) []string {
	failures := []string{}
	if input.CoverageUniverse.CompletenessDeclaration == "full_repository" {
		for _, requirement := range input.Source.Requirements {
			if !inOwnerScope(requirement.OwnerID, ownerSet) {
				failures = append(failures, "full_repository_source_requirement_outside_owner_scope:"+requirement.RequirementID)
			}
		}
	}
	if input.Inventory != nil {
		for _, entry := range input.Inventory.Inventory.Entries {
			if !inOwnerScope(entry.OwnerID, ownerSet) {
				failures = append(failures, "inventory_entry_owner_outside_scope:"+entry.TestID+":"+entry.OwnerID)
			}
		}
	}
	return failures
}

func scopedSourceRequirements(source requirementsourceadmission.Source, ownerSet map[string]struct{}) []requirementsourceadmission.Requirement {
	result := make([]requirementsourceadmission.Requirement, 0, len(source.Requirements))
	for _, requirement := range source.Requirements {
		if inOwnerScope(requirement.OwnerID, ownerSet) {
			result = append(result, requirement)
		}
	}
	return result
}

func scopedSourceRequirementIDs(source requirementsourceadmission.Source, ownerSet map[string]struct{}) []string {
	result := make([]string, 0, len(source.Requirements))
	for _, requirement := range scopedSourceRequirements(source, ownerSet) {
		result = append(result, requirement.RequirementID)
	}
	return sortedUnique(result)
}

func scopedProofCommandIDs(input compositeInput, ownerSet map[string]struct{}) []string {
	result := []string{}
	for _, requirement := range scopedSourceRequirements(input.Source, ownerSet) {
		proof, ok := input.Proof.Requirements[requirement.RequirementID]
		if !ok {
			continue
		}
		result = append(result, proof.CommandIDs...)
	}
	return sortedUnique(result)
}

func scopedProofWitnessRefs(input compositeInput, ownerSet map[string]struct{}) []string {
	result := []string{}
	for _, requirement := range scopedSourceRequirements(input.Source, ownerSet) {
		proof, ok := input.Proof.Requirements[requirement.RequirementID]
		if !ok {
			continue
		}
		result = append(result, proof.WitnessRefs...)
		result = append(result, proof.WitnessSelectors...)
	}
	return sortedUnique(result)
}

func sourceRequirementByID(source requirementsourceadmission.Source, requirementID string) (requirementsourceadmission.Requirement, bool) {
	for _, requirement := range source.Requirements {
		if requirement.RequirementID == requirementID {
			return requirement, true
		}
	}
	return requirementsourceadmission.Requirement{}, false
}

func inOwnerScope(ownerID string, ownerSet map[string]struct{}) bool {
	_, ok := ownerSet[ownerID]
	return ok
}

func requirementState(requirement requirementsourceadmission.Requirement, entries []testevidenceinventory.Entry, inventory *testevidenceinventory.Result, hasProof bool) (string, string) {
	if requirement.ClaimLevel == "deferred" {
		return "deferred_with_owner", ""
	}
	if requirement.Lifecycle.State == "removed" {
		return "not_applicable", ""
	}
	if !hasProof {
		return "missing_proof_binding_route", ""
	}
	if inventory == nil {
		return "missing_test_inventory", ""
	}
	if inventory.Report.State != "passed" {
		return "missing_test_inventory", ""
	}
	return strongestEntryState(entries)
}
func strongestEntryState(entries []testevidenceinventory.Entry) (string, string) {
	priority := []struct {
		class string
		state string
	}{
		{"semantic_falsifier", "covered_by_semantic_falsifier"},
		{"property_or_fuzz", "covered_by_property_or_fuzz"},
		{"contract_admission", "covered_by_contract_admission"},
		{"governance_or_release", "covered_by_governance_invariant_nonproduct"},
		{"benchmark", "benchmark_advisory_missing_policy"},
		{"proof_route_candidate", "proof_route_candidate_only"},
		{"routing_smoke_nonclaim", "route_only_nonclaim"},
		{"helper_or_testkit", "helper_or_testkit_nonclaim"},
	}
	for _, candidate := range priority {
		for _, entry := range entries {
			if entry.EvidenceClass == candidate.class {
				return candidate.state, candidate.class
			}
		}
	}
	return "missing_test_inventory", ""
}
func commandState(entries []testevidenceinventory.Entry) string {
	for _, entry := range entries {
		if entry.EvidenceClass == "semantic_falsifier" {
			return "command_semantic_falsifier_present"
		}
	}
	for _, entry := range entries {
		if entry.EvidenceClass == "benchmark" ||
			entry.EvidenceClass == "contract_admission" ||
			entry.EvidenceClass == "governance_or_release" ||
			entry.EvidenceClass == "helper_or_testkit" ||
			entry.EvidenceClass == "property_or_fuzz" {
			return "command_owner_nonsemantic_evidence"
		}
	}
	for _, entry := range entries {
		if entry.EvidenceClass == "proof_route_candidate" {
			return "command_proof_route_candidate_only"
		}
	}
	for _, entry := range entries {
		if entry.EvidenceClass == "routing_smoke_nonclaim" {
			return "command_route_only_nonclaim"
		}
	}
	return "missing_command_semantic_falsifier"
}
func requirementBlocks(requirement requirementsourceadmission.Requirement, state string, scope string) bool {
	if requirement.ClaimLevel != "blocking" || requirement.Lifecycle.State != "active" || scope == "selected_paths_advisory" {
		return false
	}
	switch state {
	case "covered_by_semantic_falsifier", "covered_by_property_or_fuzz", "covered_by_contract_admission", "not_applicable", "deferred_with_owner":
		return false
	default:
		return true
	}
}
func requirementWarns(requirement requirementsourceadmission.Requirement, state string, scope string) bool {
	if scope == "selected_paths_advisory" {
		return state != "covered_by_semantic_falsifier" && state != "covered_by_property_or_fuzz" && state != "covered_by_contract_admission"
	}
	return requirement.ClaimLevel != "blocking" && state != "covered_by_semantic_falsifier" && state != "covered_by_property_or_fuzz" && state != "covered_by_contract_admission"
}
func unknownInventoryRefs(entries []testevidenceinventory.Entry, requirements map[string]struct{}, invariants map[string]struct{}, commands map[string]struct{}, witnesses map[string]struct{}) []string {
	failures := []string{}
	for _, entry := range entries {
		failures = append(failures, unknownRefs(entry.TestID, "unknown_requirement_ref", entry.RequirementRefs, requirements)...)
		failures = append(failures, unknownRefs(entry.TestID, "unknown_owner_invariant_ref", entry.OwnerInvariantRefs, invariants)...)
		failures = append(failures, unknownRefs(entry.TestID, "unknown_command_or_witness_ref", entry.CommandRefs, commands)...)
		failures = append(failures, unknownRefs(entry.TestID, "unknown_command_or_witness_ref", entry.WitnessRefs, witnesses)...)
	}
	return failures
}
func unknownRefs(testID string, kind string, refs []string, known map[string]struct{}) []string {
	failures := []string{}
	for _, ref := range refs {
		if _, ok := known[ref]; !ok {
			failures = append(failures, kind+":"+testID+":"+ref)
		}
	}
	return failures
}
func entriesReferencingRequirement(entries []testevidenceinventory.Entry, requirementID string) []testevidenceinventory.Entry {
	result := []testevidenceinventory.Entry{}
	for _, entry := range entries {
		if containsString(entry.RequirementRefs, requirementID) {
			result = append(result, entry)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].TestID < result[right].TestID })
	return result
}
func entriesReferencingOwnerInvariant(entries []testevidenceinventory.Entry, invariantID string) []testevidenceinventory.Entry {
	result := []testevidenceinventory.Entry{}
	for _, entry := range entries {
		if containsString(entry.OwnerInvariantRefs, invariantID) {
			result = append(result, entry)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].TestID < result[right].TestID })
	return result
}
func entriesReferencingCommand(entries []testevidenceinventory.Entry, commandID string) []testevidenceinventory.Entry {
	result := []testevidenceinventory.Entry{}
	for _, entry := range entries {
		if containsString(entry.CommandRefs, commandID) {
			result = append(result, entry)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].TestID < result[right].TestID })
	return result
}
func guidanceSummary(state string, failures []string, warnings []string) map[string]any {
	nextAction := "Inspect caller-owned coverage classifications before making repository policy decisions."
	if state == "failed" {
		nextAction = "Repair missing semantic falsifiers, unknown refs, or failed inventory before using this view as merge-adjacent guidance."
	}
	return map[string]any{
		"failureCount": len(failures),
		"nextAction":   nextAction,
		"nonClaim":     "Guidance summary does not execute tests, approve edits, or replace caller-owned review.",
		"state":        state,
		"warningCount": len(warnings),
	}
}
