package requirementcoverageview

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func expectedCoverageRowDiagnostics(row map[string]any, rowsKey string, completenessDeclaration string) ([]string, []string) {
	state := stringValue(row["coverageState"])
	switch rowsKey {
	case "requirementCoverage":
		failures := expectedRequirementFailures(row, state, completenessDeclaration)
		warnings := []string{}
		if requirementMappingWarns(stringValue(row["claimLevel"]), state, completenessDeclaration) {
			warnings = append(warnings, state+":"+stringValue(row["requirementId"]))
		}
		return failures, warnings
	case "ownerInvariantCoverage":
		if ownerInvariantCoverageStateWarns(state) {
			return nil, []string{"missing_owner_invariant_inventory:" + stringValue(row["ownerInvariantId"])}
		}
		return nil, nil
	case "commandCoverage":
		return commandCoverageDiagnostics(stringValue(row["commandId"]), state, completenessDeclaration)
	default:
		return nil, nil
	}
}

func requireExactDiagnosticClass(actual []string, expected []string, context string, prefixes ...string) error {
	filtered := make([]string, 0, len(actual))
	for _, diagnostic := range actual {
		for _, prefix := range prefixes {
			if strings.HasPrefix(diagnostic, prefix) {
				filtered = append(filtered, diagnostic)
				break
			}
		}
	}
	if !slices.Equal(filtered, expected) {
		return fmt.Errorf("requirement coverage output %s are inconsistent with retained projection", context)
	}
	return nil
}

func admitCoverageDeadZones(raw any) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement coverage output deadZones must be an array")
	}
	result := make([]map[string]any, 0, len(values))
	previousID := ""
	for index, rawValue := range values {
		record, ok := rawValue.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement coverage output deadZones[%d] must be an object", index)
		}
		context := fmt.Sprintf("requirement coverage output deadZones[%d]", index)
		if err := admit.KnownKeys(record, []string{"deadZoneKind", "ownerId", "path", "surfaceId"}, context); err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["deadZoneKind"], map[string]struct{}{
			"unbound_code_surface": {}, "unbound_spec_surface": {}, "unbound_test_surface": {},
		}, context+" deadZoneKind")
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], context+" ownerId")
		if err != nil {
			return nil, err
		}
		path, err := admit.SafeRepoRelativePath(stringValue(record["path"]), context+" path")
		if err != nil {
			return nil, err
		}
		surfaceID, err := admit.RuleID(record["surfaceId"], context+" surfaceId")
		if err != nil {
			return nil, err
		}
		if previousID != "" && previousID >= surfaceID {
			return nil, fmt.Errorf("requirement coverage output deadZones must be sorted and unique by surfaceId")
		}
		previousID = surfaceID
		result = append(result, map[string]any{"deadZoneKind": kind, "ownerId": ownerID, "path": path, "surfaceId": surfaceID})
	}
	return result, nil
}

func admitCoverageDiagnostics(record map[string]any, rowsKey string, countKey string) ([]string, error) {
	values, err := admit.PreserveSortedTextArray(record[rowsKey], "requirement coverage output "+rowsKey, true)
	if err != nil {
		return nil, err
	}
	if !wireCountEquals(record[countKey], len(values)) {
		return nil, fmt.Errorf("requirement coverage output %s does not match %s", countKey, rowsKey)
	}
	return values, nil
}

func requireExactDerivedValue(actual any, expected any, context string) error {
	actualBytes, err := stablejson.Marshal(actual)
	if err != nil {
		return fmt.Errorf("%s must be canonical JSON: %w", context, err)
	}
	expectedBytes, err := stablejson.Marshal(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		return fmt.Errorf("%s is inconsistent with its owner inputs", context)
	}
	return nil
}

func requireExactRowDiagnostics(actual []string, expected []string, context string) error {
	filtered := make([]string, 0, len(actual))
	for _, diagnostic := range actual {
		if isCoverageRowDiagnostic(diagnostic) {
			filtered = append(filtered, diagnostic)
		}
	}
	if !slices.Equal(filtered, expected) {
		return fmt.Errorf("requirement coverage output %s contain diagnostics inconsistent with retained rows", context)
	}
	return nil
}

func admitRetainedUnknownReferenceDiagnostics(record map[string]any, failures []string, registry map[string]projectedTestRecord) error {
	knownRequirements := map[string]struct{}{}
	knownOwnerInvariants := map[string]struct{}{}
	knownCommands := map[string]struct{}{}
	knownWitnesses := map[string]struct{}{}
	for _, raw := range record["requirementCoverage"].([]any) {
		row := raw.(map[string]any)
		knownRequirements[stringValue(row["requirementId"])] = struct{}{}
		for _, witness := range append(stringArray(row["witnessRefs"]), stringArray(row["witnessSelectors"])...) {
			knownWitnesses[witness] = struct{}{}
		}
	}
	for _, raw := range record["ownerInvariantCoverage"].([]any) {
		knownOwnerInvariants[stringValue(raw.(map[string]any)["ownerInvariantId"])] = struct{}{}
	}
	for _, raw := range record["commandCoverage"].([]any) {
		knownCommands[stringValue(raw.(map[string]any)["commandId"])] = struct{}{}
	}

	entries := make([]testevidenceinventory.Entry, 0, len(registry))
	for _, projected := range registry {
		entries = append(entries, projected.entry)
	}
	expected := sortedUnique(unknownInventoryRefs(entries, knownRequirements, knownOwnerInvariants, knownCommands, knownWitnesses))
	actual := []string{}
	for _, diagnostic := range failures {
		if isUnknownReferenceDiagnosticForRetainedTest(diagnostic, registry) {
			actual = append(actual, diagnostic)
		}
	}
	actual = sortedUnique(actual)
	if !slices.Equal(actual, expected) {
		return fmt.Errorf("requirement coverage output unknown-reference diagnostics are inconsistent with retained projected tests")
	}
	return nil
}

func isUnknownReferenceDiagnosticForRetainedTest(diagnostic string, registry map[string]projectedTestRecord) bool {
	for _, kind := range []string{"unknown_requirement_ref", "unknown_owner_invariant_ref", "unknown_command_or_witness_ref"} {
		for testID := range registry {
			if strings.HasPrefix(diagnostic, kind+":"+testID+":") {
				return true
			}
		}
	}
	return false
}

func isCoverageRowDiagnostic(diagnostic string) bool {
	if diagnostic == "missing_test_inventory:input" {
		return false
	}
	prefix, _, ok := strings.Cut(diagnostic, ":")
	if !ok {
		return false
	}
	if _, ok := requirementCoverageStateDescriptor(prefix); ok {
		return true
	}
	switch prefix {
	case "missing_owner_invariant_inventory",
		missingCommandCoverageState,
		"nonsemantic_command_evidence",
		"command_route_only_nonclaim",
		"command_proof_route_candidate_only":
		return true
	default:
		return false
	}
}
