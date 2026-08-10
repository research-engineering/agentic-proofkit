package requirementcoverageview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var outputKeys = []string{
	"authority", "bindingId", "commandCoverage", "commandCoverageCount",
	"completenessDeclaration", "contractId", "coverageBasis", "coverageUniverseId", "deadZones",
	"failureClassifications", "failureCount", "failures", "guidanceSummary",
	"nonClaims", "ownerInvariantCoverage", "ownerInvariantCoverageCount",
	"ownerInvariantRegistryId", "proofMode", "requirementCoverage",
	"requirementCoverageCount", "schemaVersion", "sourceId", "state",
	"testInventoryId", "unmappedTests", "viewInputId", "viewKind", "warningClassifications",
	"warningCount", "warnings",
}

type coverageRowDescriptor struct {
	rowsKey  string
	countKey string
	idKey    string
}

var coverageRowDescriptors = []coverageRowDescriptor{
	{rowsKey: "requirementCoverage", countKey: "requirementCoverageCount", idKey: "requirementId"},
	{rowsKey: "ownerInvariantCoverage", countKey: "ownerInvariantCoverageCount", idKey: "ownerInvariantId"},
	{rowsKey: "commandCoverage", countKey: "commandCoverageCount", idKey: "commandId"},
}

// AdmitOutput preserves the requirement-coverage owner's wire projection for
// parent commands and replays retained report, requirement, and owner-invariant
// derivations without claiming source authenticity.
func AdmitOutput(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement coverage output must be an object")
	}
	if err := admit.KnownKeys(record, outputKeys, "requirement coverage output"); err != nil {
		return nil, err
	}
	for _, key := range outputKeys {
		if _, ok := record[key]; !ok {
			return nil, fmt.Errorf("requirement coverage output is missing required field %s", key)
		}
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 2) && record["schemaVersion"] != 2 {
		return nil, fmt.Errorf("requirement coverage output schemaVersion must be 2")
	}
	if record["viewKind"] != "proofkit.requirement-coverage-view" || record["authority"] != "lookup_only" {
		return nil, fmt.Errorf("requirement coverage output identity is invalid")
	}
	for _, key := range []string{"viewInputId", "coverageUniverseId", "sourceId"} {
		if _, err := admit.RuleID(record[key], "requirement coverage output "+key); err != nil {
			return nil, err
		}
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement coverage output nonClaims", false)
	if err != nil {
		return nil, err
	}
	for _, nonClaim := range defaultNonClaims {
		if !slices.Contains(nonClaims, nonClaim) {
			return nil, fmt.Errorf("requirement coverage output nonClaims must retain command-owned boundary %q", nonClaim)
		}
	}
	if _, err := admit.Enum(record["state"], map[string]struct{}{"failed": {}, "passed": {}}, "requirement coverage output state"); err != nil {
		return nil, err
	}
	for _, row := range coverageRowDescriptors {
		if err := admitCoverageOutputRows(record, row.rowsKey, row.countKey, row.idKey); err != nil {
			return nil, err
		}
	}
	if err := admitNestedRecords(record["unmappedTests"], projectedTestKeys, "requirement coverage output unmappedTests"); err != nil {
		return nil, err
	}
	if err := validateCoverageOutputSemantics(record); err != nil {
		return nil, err
	}
	findings, err := secretjson.Scan(record, "requirement_coverage_output")
	if err != nil || len(findings) > 0 {
		return nil, fmt.Errorf("requirement coverage output contains secret-shaped data")
	}
	encoded, err := stablejson.Marshal(record)
	if err != nil {
		return nil, err
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, err
	}
	return decoded.(map[string]any), nil
}

// SelectRequirements returns a bounded lookup fragment. It is deliberately not
// another complete coverage report, so omitted rows cannot affect report state
// or dead-zone claims.
func SelectRequirements(output map[string]any, selected map[string]struct{}) map[string]any {
	rows := make([]any, 0)
	for _, raw := range output["requirementCoverage"].([]any) {
		row := raw.(map[string]any)
		if _, ok := selected[row["requirementId"].(string)]; ok {
			rows = append(rows, cloneCoverageJSONValue(row))
		}
	}
	return map[string]any{
		"authority":                "lookup_fragment_only",
		"nonClaims":                admit.StringSliceToAny(defaultNonClaims),
		"requirementCoverage":      rows,
		"requirementCoverageCount": len(rows),
		"schemaVersion":            json.Number("1"),
		"sourceViewInputId":        output["viewInputId"],
		"viewKind":                 "proofkit.requirement-coverage-fragment",
	}
}

func admitCoverageOutputRows(record map[string]any, rowsKey, countKey, idKey string) error {
	rows, ok := record[rowsKey].([]any)
	if !ok {
		return fmt.Errorf("requirement coverage output %s must be an array", rowsKey)
	}
	if !wireCountEquals(record[countKey], len(rows)) {
		return fmt.Errorf("requirement coverage output %s does not match %s", countKey, rowsKey)
	}
	previousID := ""
	for index, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("requirement coverage output %s[%d] must be an object", rowsKey, index)
		}
		rowKeys := coverageRowKeys(rowsKey)
		if err := admit.KnownKeys(row, rowKeys, "requirement coverage output "+rowsKey); err != nil {
			return err
		}
		for _, key := range rowKeys {
			if _, ok := row[key]; !ok {
				return fmt.Errorf("requirement coverage output %s[%d] is missing required field %s", rowsKey, index, key)
			}
		}
		if err := admitCoverageNestedRows(row, rowsKey); err != nil {
			return err
		}
		id, err := admit.RuleID(row[idKey], fmt.Sprintf("requirement coverage output %s[%d].%s", rowsKey, index, idKey))
		if err != nil {
			return err
		}
		if previousID != "" && previousID >= id {
			return fmt.Errorf("requirement coverage output %s must be sorted and unique by %s", rowsKey, idKey)
		}
		previousID = id
	}
	return nil
}

func cloneCoverageJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, child := range typed {
			cloned[key] = cloneCoverageJSONValue(child)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for index, child := range typed {
			cloned[index] = cloneCoverageJSONValue(child)
		}
		return cloned
	default:
		return typed
	}
}

func admitCoverageNestedRows(row map[string]any, rowsKey string) error {
	if err := admitNestedRecords(row["tests"], projectedTestKeys, "requirement coverage output tests"); err != nil {
		return err
	}
	for _, raw := range row["tests"].([]any) {
		test := raw.(map[string]any)
		if err := admitNestedRecords(test["qualityFindings"], projectedQualityFindingKeys, "requirement coverage output quality findings"); err != nil {
			return err
		}
	}
	if rowsKey == "requirementCoverage" {
		return admitNestedRecords(row["scenarios"], []string{"commandIds", "environmentClasses", "scenarioId", "verifyCommands", "witnessId", "witnessKind", "witnessPath", "witnessSelectors"}, "requirement coverage output scenarios")
	}
	return nil
}

func admitNestedRecords(raw any, keys []string, context string) error {
	values, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", context)
	}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d] must be an object", context, index)
		}
		if err := admit.KnownKeys(record, keys, context); err != nil {
			return err
		}
	}
	return nil
}

func coverageRowKeys(rowsKey string) []string {
	switch rowsKey {
	case "requirementCoverage":
		return []string{"claimLevel", "commandIds", "coverageState", "environmentClasses", "evidenceClass", "failures", "invariant", "lifecycleState", "nonClaims", "ownerId", "proofState", "requirementId", "scenarioCount", "scenarios", "specPath", "testIds", "tests", "verifyCommands", "witnessRefs", "witnessSelectors"}
	case "ownerInvariantCoverage":
		return []string{"coverageState", "evidenceClass", "nonClaims", "ownerId", "ownerInvariantId", "sourcePath", "summary", "testIds", "tests", "warnings"}
	case "commandCoverage":
		return []string{"commandId", "coverageState", "failures", "testIds", "tests"}
	default:
		return nil
	}
}

func wireCountEquals(raw any, expected int) bool {
	switch value := raw.(type) {
	case int:
		return value == expected
	case json.Number:
		if expected == 0 {
			return admit.JSONNumberEquals(value, 0)
		}
		actual, err := admit.PositiveInteger(value, "requirement coverage output count")
		return err == nil && actual == expected
	default:
		return false
	}
}
