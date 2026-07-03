package migrationparityadmission

import (
	"encoding/json"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const otherDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestBuildAdmitsMatchedParityAndRejectsDigestDrift(t *testing.T) {
	input := validMigrationParityInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input = validMigrationParityInput()
	input["parityRecords"].([]any)[0].(map[string]any)["proofkitDigest"] = otherDigest
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(mutated) error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(mutated) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func validMigrationParityInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"paritySetId":   "proofkit.test.parity",
		"sourceProofOwners": []any{
			map[string]any{"ownerId": "proofkit.test.legacy", "ownerKind": "local_script", "path": "scripts/legacy.js"},
		},
		"targetProofkitRefs": []any{
			map[string]any{"targetId": "proofkit.test.target", "targetKind": "proofkit_report", "path": "artifacts/proofkit/report.json"},
		},
		"parityRecords": []any{
			map[string]any{
				"equivalenceKind":    "report_summary_projection",
				"evidenceId":         "proofkit.test.evidence",
				"evidenceRefs":       []any{"artifacts/proofkit/parity.json"},
				"legacyDigest":       testDigest,
				"legacySubjectRef":   "legacy.report",
				"nonClaims":          []any{"Migration parity test fixture does not prove semantic adequacy."},
				"proofkitDigest":     testDigest,
				"proofkitSubjectRef": "proofkit.report",
				"reason":             "same admitted projection",
				"receiptRefs":        []any{},
				"sourceOwnerId":      "proofkit.test.legacy",
				"status":             "matched",
				"targetId":           "proofkit.test.target",
			},
		},
		"nonClaims": []any{"Migration parity test input is not rollout proof."},
	}
}
