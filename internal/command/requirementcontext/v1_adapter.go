package requirementcontext

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var v1BoundaryNonClaims = []string{
	"Requirement context is a derived projection and is not requirement, proof, coverage, merge, release, rollout, or readiness authority.",
	"Requirement context does not execute native witnesses or prove source freshness after composition.",
}

func admitV1Snapshot(record map[string]any) (Snapshot, error) {
	if err := admit.KnownKeys(record, []string{"baselineVerification", "catalogId", "contextKind", "nonClaims", "projections", "schemaVersion", "snapshotId", "sources"}, "requirement context v1"); err != nil {
		return Snapshot{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["contextKind"] != ContextKind {
		return Snapshot{}, fmt.Errorf("requirement context v1 identity is invalid")
	}
	verification, err := admit.Enum(record["baselineVerification"], map[string]struct{}{"partially_verified": {}, "unverified": {}, "verified": {}}, "requirement context v1 baselineVerification")
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := admitSnapshotRecord(record, v1BoundaryNonClaims)
	if err != nil {
		return Snapshot{}, err
	}
	coverage := expectedDigestCoverage(snapshot.Sources)
	if verification != v1VerificationValue(coverage) {
		return Snapshot{}, fmt.Errorf("requirement context v1 baselineVerification does not match admitted sources")
	}
	snapshot.ExpectedDigestCoverage = coverage
	return validateSnapshotSize(snapshot)
}

func v1VerificationValue(coverage string) string {
	switch coverage {
	case "none":
		return "unverified"
	case "partial":
		return "partially_verified"
	default:
		return "verified"
	}
}
