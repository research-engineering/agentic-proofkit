package requirementcoverageview

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var outputKeys = []string{
	"authority", "bindingId", "commandCoverage", "commandCoverageCount",
	"completenessDeclaration", "contractId", "coverageUniverseId", "deadZones",
	"failureClassifications", "failureCount", "failures", "guidanceSummary",
	"nonClaims", "ownerInvariantCoverage", "ownerInvariantCoverageCount",
	"ownerInvariantRegistryId", "proofMode", "requirementCoverage",
	"requirementCoverageCount", "schemaVersion", "sourceId", "state",
	"testInventoryId", "viewInputId", "viewKind", "warningClassifications",
	"warningCount", "warnings",
}

// AdmitOutput preserves the requirement-coverage owner's wire projection for
// parent commands without reinterpreting coverage semantics.
func AdmitOutput(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement coverage output must be an object")
	}
	if err := admit.KnownKeys(record, outputKeys, "requirement coverage output"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) && record["schemaVersion"] != 1 {
		return nil, fmt.Errorf("requirement coverage output schemaVersion must be 1")
	}
	if record["viewKind"] != "proofkit.requirement-coverage-view" || record["authority"] != "lookup_only" {
		return nil, fmt.Errorf("requirement coverage output identity is invalid")
	}
	for _, key := range []string{"viewInputId", "coverageUniverseId", "sourceId"} {
		if _, err := admit.RuleID(record[key], "requirement coverage output "+key); err != nil {
			return nil, err
		}
	}
	if _, err := admit.Enum(record["state"], map[string]struct{}{"failed": {}, "passed": {}}, "requirement coverage output state"); err != nil {
		return nil, err
	}
	for _, row := range []struct {
		rowsKey  string
		countKey string
		idKey    string
	}{
		{rowsKey: "requirementCoverage", countKey: "requirementCoverageCount", idKey: "requirementId"},
		{rowsKey: "ownerInvariantCoverage", countKey: "ownerInvariantCoverageCount", idKey: "ownerInvariantId"},
		{rowsKey: "commandCoverage", countKey: "commandCoverageCount", idKey: "commandId"},
	} {
		if err := admitCoverageOutputRows(record, row.rowsKey, row.countKey, row.idKey); err != nil {
			return nil, err
		}
	}
	for _, pair := range [][2]string{{"failures", "failureCount"}, {"warnings", "warningCount"}} {
		if err := admitCountedArray(record, pair[0], pair[1]); err != nil {
			return nil, err
		}
	}
	if _, ok := record["deadZones"].([]any); !ok {
		return nil, fmt.Errorf("requirement coverage output deadZones must be an array")
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
			rows = append(rows, row)
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
	seen := map[string]struct{}{}
	for index, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("requirement coverage output %s[%d] must be an object", rowsKey, index)
		}
		if err := admit.KnownKeys(row, coverageRowKeys(rowsKey), "requirement coverage output "+rowsKey); err != nil {
			return err
		}
		if err := admitCoverageNestedRows(row, rowsKey); err != nil {
			return err
		}
		id, err := admit.RuleID(row[idKey], fmt.Sprintf("requirement coverage output %s[%d].%s", rowsKey, index, idKey))
		if err != nil {
			return err
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("requirement coverage output %s identities must be unique", rowsKey)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func admitCoverageNestedRows(row map[string]any, rowsKey string) error {
	if rowsKey == "commandCoverage" {
		return nil
	}
	if err := admitNestedRecords(row["tests"], []string{"commandRefs", "evidenceClass", "expectedPublicOutcome", "negativeCaseId", "nonClaims", "oracleKind", "oracleSummary", "qualityFindings", "selector", "sourcePath", "testId", "witnessRefs", "wrongImplementationClassId"}, "requirement coverage output tests"); err != nil {
		return err
	}
	for _, raw := range row["tests"].([]any) {
		test := raw.(map[string]any)
		if err := admitNestedRecords(test["qualityFindings"], []string{"class", "evidenceRefs", "findingId", "nonClaims", "ownerReviewState", "severity"}, "requirement coverage output quality findings"); err != nil {
			return err
		}
	}
	if rowsKey == "requirementCoverage" {
		return admitNestedRecords(row["scenarios"], []string{"commandIds", "environmentClasses", "scenarioId", "witnessId", "witnessKind", "witnessPath"}, "requirement coverage output scenarios")
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
		return []string{"commandId", "coverageState", "failures", "testIds"}
	default:
		return nil
	}
}

func admitCountedArray(record map[string]any, rowsKey, countKey string) error {
	rows, ok := record[rowsKey].([]any)
	if !ok {
		return fmt.Errorf("requirement coverage output %s must be an array", rowsKey)
	}
	if !wireCountEquals(record[countKey], len(rows)) {
		return fmt.Errorf("requirement coverage output %s does not match %s", countKey, rowsKey)
	}
	return nil
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
