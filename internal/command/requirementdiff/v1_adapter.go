package requirementdiff

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func admitV1DiffInput(record map[string]any) error {
	return requireContextVersions(record, 1)
}

func admitV1Output(record map[string]any, currentSnapshotID string) (map[string]any, error) {
	if err := admit.KnownKeys(record, []string{"baseBaselineVerification", "baseSnapshotId", "changeCount", "changes", "currentBaselineVerification", "currentSnapshotId", "diffId", "diffKind", "nonClaims", "schemaVersion"}, "requirement semantic diff output v1"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) && record["schemaVersion"] != 1 {
		return nil, fmt.Errorf("requirement semantic diff output schemaVersion must be 1")
	}
	if record["diffKind"] != "proofkit.requirement-semantic-diff" || record["currentSnapshotId"] != currentSnapshotID {
		return nil, fmt.Errorf("requirement semantic diff output identity is invalid")
	}
	coverage := map[string]string{}
	for _, key := range []string{"baseBaselineVerification", "currentBaselineVerification"} {
		value, err := admit.Enum(record[key], map[string]struct{}{"partially_verified": {}, "unverified": {}, "verified": {}}, "requirement semantic diff output v1 "+key)
		if err != nil {
			return nil, err
		}
		coverage[key] = v1CoverageValue(value)
	}
	admitted, err := admitOutputRecord(record)
	if err != nil {
		return nil, err
	}
	delete(admitted, "baseBaselineVerification")
	delete(admitted, "currentBaselineVerification")
	admitted["baseExpectedDigestCoverage"] = coverage["baseBaselineVerification"]
	admitted["currentExpectedDigestCoverage"] = coverage["currentBaselineVerification"]
	admitted["schemaVersion"] = json.Number("2")
	return canonicalCopy(admitted)
}

func v1CoverageValue(value string) string {
	switch value {
	case "unverified":
		return "none"
	case "partially_verified":
		return "partial"
	default:
		return "all"
	}
}
