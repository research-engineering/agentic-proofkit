package requirementcoverageview

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func validateCoverageOutputSemantics(record map[string]any) error {
	proofMode, err := admit.Enum(record["proofMode"], map[string]struct{}{"compact": {}, "structured": {}}, "requirement coverage output proofMode")
	if err != nil {
		return err
	}
	if err := admitCoverageOutputIdentity(record, proofMode); err != nil {
		return err
	}
	completenessDeclaration, err := admit.Enum(record["completenessDeclaration"], map[string]struct{}{
		"full_repository": {}, "selected_owner_surfaces": {}, "selected_paths_advisory": {},
	}, "requirement coverage output completenessDeclaration")
	if err != nil {
		return err
	}
	failures, err := admitCoverageDiagnostics(record, "failures", "failureCount")
	if err != nil {
		return err
	}
	warnings, err := admitCoverageDiagnostics(record, "warnings", "warningCount")
	if err != nil {
		return err
	}
	expectedState := "passed"
	if len(failures) > 0 {
		expectedState = "failed"
	}
	if record["state"] != expectedState {
		return fmt.Errorf("requirement coverage output state is inconsistent with failures")
	}
	if err := requireExactDerivedValue(record["failureClassifications"], mapsToAny(diagnosticClassifications(failures, "failure")), "failureClassifications"); err != nil {
		return err
	}
	if err := requireExactDerivedValue(record["warningClassifications"], mapsToAny(diagnosticClassifications(warnings, "warning")), "warningClassifications"); err != nil {
		return err
	}
	if err := requireExactDerivedValue(record["guidanceSummary"], guidanceSummary(expectedState, failures, warnings), "guidanceSummary"); err != nil {
		return err
	}
	deadZones, err := admitCoverageDeadZones(record["deadZones"])
	if err != nil {
		return err
	}
	deadZoneFailures := []string{}
	deadZoneWarnings := []string{}
	if completenessDeclaration == "selected_paths_advisory" {
		deadZoneWarnings = deadZoneDiagnostics("dead_zone_advisory", deadZones)
	} else {
		deadZoneFailures = deadZoneDiagnostics("dead_zone", deadZones)
	}
	if err := requireExactDiagnosticClass(failures, deadZoneFailures, "dead-zone failures", "dead_zone:", "dead_zone_advisory:"); err != nil {
		return err
	}
	if err := requireExactDiagnosticClass(warnings, deadZoneWarnings, "dead-zone warnings", "dead_zone:", "dead_zone_advisory:"); err != nil {
		return err
	}
	inventoryMissing := record["testInventoryId"] == nil
	if slices.Contains(warnings, "missing_test_inventory:input") != inventoryMissing {
		return fmt.Errorf("requirement coverage output missing_test_inventory:input warning is inconsistent with testInventoryId")
	}
	projectedTests, err := admitCoverageProjectedTestRegistry(record)
	if err != nil {
		return err
	}
	projectedEntries := projectedRegistryEntries(projectedTests)
	coverageBasis, err := admitCoverageBasis(record["coverageBasis"], inventoryMissing, completenessDeclaration, projectedEntries)
	if err != nil {
		return err
	}
	if err := requireExactDiagnosticClass(
		failures,
		coverageBasis.ownerScopeFailures,
		"owner-scope failures",
		"full_repository_source_requirement_outside_owner_scope:",
		"inventory_entry_owner_outside_scope:",
	); err != nil {
		return err
	}
	inventoryUnavailable := inventoryMissing
	expectedInventoryFailures := []string{}
	if inventoryUnavailable {
		if len(projectedEntries) != 0 {
			return fmt.Errorf("requirement coverage output without testInventoryId must not retain projected tests")
		}
	} else {
		inventoryFailures, _, err := testevidenceinventory.ClassifyProjectedEntries(projectedEntries)
		if err != nil {
			return err
		}
		if len(inventoryFailures) > 0 {
			inventoryUnavailable = true
			expectedInventoryFailures = []string{"test_inventory_failed:" + record["testInventoryId"].(string)}
		}
	}
	if err := requireExactDiagnosticClass(failures, expectedInventoryFailures, "test-inventory failures", "test_inventory_failed:"); err != nil {
		return err
	}
	if err := admitProjectedParentClosure(record, projectedTests); err != nil {
		return err
	}
	requiredFailures := []string{}
	requiredWarnings := []string{}
	for _, descriptor := range coverageRowDescriptors {
		rowsKey := descriptor.rowsKey
		rows, ok := record[rowsKey].([]any)
		if !ok {
			return fmt.Errorf("requirement coverage output %s must be an array", rowsKey)
		}
		for index, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("requirement coverage output %s[%d] must be an object", rowsKey, index)
			}
			if err := admitCoverageRowSemantics(row, rowsKey, index, proofMode, inventoryUnavailable, completenessDeclaration, coverageBasis.ownerSet); err != nil {
				return err
			}
			rowFailures, rowWarnings := expectedCoverageRowDiagnostics(row, rowsKey, proofMode, completenessDeclaration)
			requiredFailures = append(requiredFailures, rowFailures...)
			requiredWarnings = append(requiredWarnings, rowWarnings...)
		}
	}
	if err := requireExactRowDiagnostics(failures, sortedUnique(requiredFailures), "failures"); err != nil {
		return err
	}
	if err := requireExactRowDiagnostics(warnings, sortedUnique(requiredWarnings), "warnings"); err != nil {
		return err
	}
	if err := admitRetainedUnknownReferenceDiagnostics(record, failures, projectedTests); err != nil {
		return err
	}
	return nil
}

func admitCoverageOutputIdentity(record map[string]any, proofMode string) error {
	bindingID, bindingOK := record["bindingId"].(string)
	contractID, contractOK := record["contractId"].(string)
	if !bindingOK || !contractOK {
		return fmt.Errorf("requirement coverage output bindingId and contractId must be strings")
	}
	if proofMode == "structured" {
		if _, err := admit.RuleID(bindingID, "requirement coverage output bindingId"); err != nil {
			return err
		}
		if contractID != "" {
			return fmt.Errorf("requirement coverage structured output contractId must be empty")
		}
	} else {
		if bindingID != "" {
			return fmt.Errorf("requirement coverage compact output bindingId must be empty")
		}
		if _, err := admit.RuleID(contractID, "requirement coverage output contractId"); err != nil {
			return err
		}
	}
	registryID, ok := record["ownerInvariantRegistryId"].(string)
	if !ok {
		return fmt.Errorf("requirement coverage output ownerInvariantRegistryId must be a string")
	}
	if registryID != "" {
		if _, err := admit.RuleID(registryID, "requirement coverage output ownerInvariantRegistryId"); err != nil {
			return err
		}
	}
	if record["testInventoryId"] != nil {
		if _, err := admit.RuleID(record["testInventoryId"], "requirement coverage output testInventoryId"); err != nil {
			return err
		}
	}
	return nil
}

func admitCoverageRowSemantics(row map[string]any, rowsKey string, index int, proofMode string, inventoryUnavailable bool, completenessDeclaration string, ownerSet map[string]struct{}) error {
	context := fmt.Sprintf("requirement coverage output %s[%d]", rowsKey, index)
	if err := admitCoverageRowMetadata(row, rowsKey, ownerSet, context); err != nil {
		return err
	}
	entries, err := admitProjectedTestSemantics(row["tests"], context+" tests")
	if err != nil {
		return err
	}
	if err := admitExactProjectedTestIDs(row["testIds"], entries, context+" testIds"); err != nil {
		return err
	}
	if err := requireProjectedParentRef(entries, row, rowsKey, context); err != nil {
		return err
	}
	switch rowsKey {
	case "requirementCoverage":
		if err := admitCoverageStateClass(row, requirementCoverageStateDescriptor, context); err != nil {
			return err
		}
		if err := admitRequirementProofProjection(row, proofMode, entries, context); err != nil {
			return err
		}
	case "ownerInvariantCoverage":
		if err := admitCoverageStateClass(row, ownerInvariantCoverageStateDescriptor, context); err != nil {
			return err
		}
	case "commandCoverage":
		state, ok := row["coverageState"].(string)
		if !ok || !commandCoverageStateAllowed(state) {
			return fmt.Errorf("%s coverageState must be one of the admitted command coverage states", context)
		}
		expectedState := commandState(entries)
		if state != expectedState {
			return fmt.Errorf("%s coverageState is not derived from projected tests", context)
		}
		expectedFailures, _ := commandCoverageDiagnostics(stringValue(row["commandId"]), state, completenessDeclaration)
		if err := requireExactDerivedValue(row["failures"], admit.StringSliceToAny(expectedFailures), context+" failures"); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("%s has unsupported row kind", context)
	}
	state := stringValue(row["coverageState"])
	class := stringValue(row["evidenceClass"])
	switch rowsKey {
	case "requirementCoverage":
		expectedState, expectedClass, err := expectedRequirementCoverageState(row, proofMode, entries, inventoryUnavailable, context)
		if err != nil {
			return err
		}
		if state != expectedState || class != expectedClass {
			return fmt.Errorf("%s coverageState and evidenceClass are not derived from projected tests and lifecycle", context)
		}
		expectedFailures := expectedRequirementFailures(row, proofMode, expectedState, completenessDeclaration)
		if err := requireExactDerivedValue(row["failures"], admit.StringSliceToAny(expectedFailures), context+" failures"); err != nil {
			return err
		}
	case "ownerInvariantCoverage":
		expectedState, expectedClass := "missing_test_inventory", ""
		if !inventoryUnavailable {
			expectedState, expectedClass = strongestMappingState(entries)
		}
		if state != expectedState || class != expectedClass {
			return fmt.Errorf("%s coverageState and evidenceClass are not derived from projected tests", context)
		}
		expectedWarnings := []string{}
		if ownerInvariantCoverageStateWarns(expectedState) {
			expectedWarnings = append(expectedWarnings, "missing_owner_invariant_inventory:"+stringValue(row["ownerInvariantId"]))
		}
		if err := requireExactDerivedValue(row["warnings"], admit.StringSliceToAny(expectedWarnings), context+" warnings"); err != nil {
			return err
		}
	}
	return nil
}

func admitCoverageStateClass(row map[string]any, lookup func(string) (coverageStateDescriptor, bool), context string) error {
	state, ok := row["coverageState"].(string)
	if !ok {
		return fmt.Errorf("%s coverageState must be a string", context)
	}
	descriptor, ok := lookup(state)
	if !ok {
		return fmt.Errorf("%s coverageState is unsupported", context)
	}
	class, ok := row["evidenceClass"].(string)
	if !ok {
		return fmt.Errorf("%s evidenceClass must be a string", context)
	}
	if class != descriptor.evidenceClass {
		return fmt.Errorf("%s coverageState and evidenceClass are inconsistent", context)
	}
	if class != "" {
		if _, err := testevidenceinventory.AdmitEvidenceClass(class, context+" evidenceClass"); err != nil {
			return err
		}
	}
	return nil
}

func expectedRequirementCoverageState(row map[string]any, proofMode string, entries []testevidenceinventory.Entry, inventoryUnavailable bool, context string) (string, string, error) {
	claimLevel, ok := row["claimLevel"].(string)
	if !ok || (claimLevel != "advisory" && claimLevel != "blocking" && claimLevel != "deferred") {
		return "", "", fmt.Errorf("%s claimLevel is invalid", context)
	}
	lifecycleState, ok := row["lifecycleState"].(string)
	if !ok || (lifecycleState != "active" && lifecycleState != "deprecated" && lifecycleState != "removed" && lifecycleState != "superseded") {
		return "", "", fmt.Errorf("%s lifecycleState is invalid", context)
	}
	if claimLevel == "deferred" {
		return "deferred_with_owner", "", nil
	}
	if lifecycleState == "removed" {
		return "not_applicable", "", nil
	}
	if !outputRowHasProofRoute(row, proofMode) {
		return "missing_proof_binding_route", "", nil
	}
	if inventoryUnavailable {
		return "missing_test_inventory", "", nil
	}
	state, class := strongestMappingState(entries)
	return state, class, nil
}

func expectedRequirementFailures(row map[string]any, proofMode, state string, completenessDeclaration string) []string {
	requirementID := stringValue(row["requirementId"])
	claimLevel := stringValue(row["claimLevel"])
	lifecycleState := stringValue(row["lifecycleState"])
	failures := []string{}
	if !outputRowHasProofRoute(row, proofMode) && claimLevel == "blocking" && lifecycleState == "active" {
		failures = append(failures, "missing_proof_binding_route:"+requirementID)
	}
	if requirementMappingBlocks(claimLevel, lifecycleState, state, completenessDeclaration) {
		failures = append(failures, state+":"+requirementID)
	}
	return sortedUnique(failures)
}

func outputRowHasProofRoute(row map[string]any, proofMode string) bool {
	if proofMode == "compact" {
		scenarios, scenariosOK := row["scenarios"].([]any)
		routes, routesOK := row["declaredWitnessRoutes"].([]any)
		return scenariosOK && routesOK && len(scenarios) > 0 && len(routes) > 0
	}
	return stringValue(row["proofState"]) == "witness_backed"
}
