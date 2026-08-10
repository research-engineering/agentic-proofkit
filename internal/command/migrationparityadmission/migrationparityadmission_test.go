package migrationparityadmission

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const otherDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestBuildAdmitsCallerDeclaredMatchAndRejectsDigestDrift(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.087858357304530014219351528044382591532264544185224319857347811230381754931058")
	input := validMigrationParityInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	if record.Summary["callerDeclaredMatchCount"] != 1 || record.Summary["admittedParityClaimCount"] != 1 {
		t.Fatalf("Build() summary lost caller-declared boundary: %#v", record.Summary)
	}
	if _, exists := record.Summary["matchedCount"]; exists {
		t.Fatalf("Build() retained verification-sounding matchedCount: %#v", record.Summary)
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

func TestBuildProjectsEveryCallerDeclaredStatusAndSummaryField(t *testing.T) {
	tests := []struct {
		name             string
		status           string
		differentDigests bool
		passed           bool
		wantFindings     []string
	}{
		{name: "match equal", status: "caller_declared_match", passed: true},
		{name: "match different", status: "caller_declared_match", differentDigests: true, wantFindings: []string{"migration parity record proofkit.test.evidence declares a match but digests differ"}},
		{name: "mismatch equal", status: "caller_declared_mismatch", wantFindings: []string{"migration parity record proofkit.test.evidence declares a mismatch but digests are equal", "migration parity record proofkit.test.evidence is not admitted: caller_declared_mismatch"}},
		{name: "mismatch different", status: "caller_declared_mismatch", differentDigests: true, wantFindings: []string{"migration parity record proofkit.test.evidence is not admitted: caller_declared_mismatch"}},
		{name: "not comparable equal", status: "caller_declared_not_comparable", wantFindings: []string{"migration parity record proofkit.test.evidence is not admitted: caller_declared_not_comparable"}},
		{name: "not comparable different", status: "caller_declared_not_comparable", differentDigests: true, wantFindings: []string{"migration parity record proofkit.test.evidence is not admitted: caller_declared_not_comparable"}},
		{name: "not run equal", status: "caller_declared_not_run", wantFindings: []string{"migration parity record proofkit.test.evidence is not admitted: caller_declared_not_run"}},
		{name: "not run different", status: "caller_declared_not_run", differentDigests: true, wantFindings: []string{"migration parity record proofkit.test.evidence is not admitted: caller_declared_not_run"}},
	}
	wantSummaryKeys := []string{
		"admittedParityClaimCount",
		"callerDeclaredMatchCount",
		"callerDeclaredMismatchCount",
		"callerDeclaredNotComparableCount",
		"callerDeclaredNotRunCount",
		"failureCount",
		"parityRecordCount",
		"sourceProofOwnerCount",
		"targetProofkitRefCount",
	}
	wantDiagnosticKeys := []string{"admittedParityClaimRefs", "failures", "migrationParity"}
	statusSummaryKeys := map[string]string{
		"caller_declared_match":          "callerDeclaredMatchCount",
		"caller_declared_mismatch":       "callerDeclaredMismatchCount",
		"caller_declared_not_comparable": "callerDeclaredNotComparableCount",
		"caller_declared_not_run":        "callerDeclaredNotRunCount",
	}
	const boundaryNonClaim = "Migration parity statuses and status-derived parity claim counters are caller declarations, while structural and failure counts are Proofkit-computed admission facts; none are native verification results."

	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			input := validMigrationParityInput()
			parity := input["parityRecords"].([]any)[0].(map[string]any)
			parity["status"] = item.status
			if item.differentDigests {
				parity["proofkitDigest"] = otherDigest
			}

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if item.passed != (exitCode == 0 && record.State == "passed") {
				t.Fatalf("Build() exit=%d state=%s, passed=%v", exitCode, record.State, item.passed)
			}
			statusCountTotal := 0
			for status, summaryKey := range statusSummaryKeys {
				want := 0
				if status == item.status {
					want = 1
				}
				if record.Summary[summaryKey] != want {
					t.Fatalf("Build() %s=%#v, want %d for status %s", summaryKey, record.Summary[summaryKey], want, item.status)
				}
				statusCountTotal += record.Summary[summaryKey].(int)
			}
			if statusCountTotal != record.Summary["parityRecordCount"] {
				t.Fatalf("Build() caller-declared status total=%d, parityRecordCount=%#v", statusCountTotal, record.Summary["parityRecordCount"])
			}
			if got := sortedMapKeys(record.Summary); !slices.Equal(got, wantSummaryKeys) {
				t.Fatalf("Build() summary keys=%v, want %v", got, wantSummaryKeys)
			}
			diagnosticKeys := make([]string, 0, len(record.Diagnostics))
			var admittedRefs []any
			var failures []any
			var migrationParity []any
			for _, diagnostic := range record.Diagnostics {
				diagnosticKeys = append(diagnosticKeys, diagnostic.Key)
				if diagnostic.Key == "admittedParityClaimRefs" {
					admittedRefs = diagnostic.Value.([]any)
				}
				if diagnostic.Key == "failures" {
					failures = diagnostic.Value.([]any)
				}
				if diagnostic.Key == "migrationParity" {
					migrationParity = diagnostic.Value.([]any)
				}
			}
			sort.Strings(diagnosticKeys)
			if !slices.Equal(diagnosticKeys, wantDiagnosticKeys) {
				t.Fatalf("Build() diagnostic keys=%v, want %v", diagnosticKeys, wantDiagnosticKeys)
			}
			if len(migrationParity) != 1 || migrationParity[0].(map[string]any)["status"] != item.status {
				t.Fatalf("Build() migration parity=%#v, want status %s", migrationParity, item.status)
			}
			if got := anyStrings(migrationParity[0].(map[string]any)["findings"].([]any)); !slices.Equal(got, item.wantFindings) {
				t.Fatalf("Build() findings=%v, want %v", got, item.wantFindings)
			}
			wantRecordNonClaims := anyStrings(parity["nonClaims"].([]any))
			if got := anyStrings(migrationParity[0].(map[string]any)["nonClaims"].([]any)); !slices.Equal(got, wantRecordNonClaims) {
				t.Fatalf("Build() record nonClaims=%v, want exact caller-declared boundary %v", got, wantRecordNonClaims)
			}
			for key, want := range map[string]int{
				"admittedParityClaimCount": len(admittedRefs),
				"failureCount":             len(failures),
				"parityRecordCount":        len(input["parityRecords"].([]any)),
				"sourceProofOwnerCount":    len(input["sourceProofOwners"].([]any)),
				"targetProofkitRefCount":   len(input["targetProofkitRefs"].([]any)),
			} {
				if record.Summary[key] != want {
					t.Fatalf("Build() %s=%#v, want computed %d", key, record.Summary[key], want)
				}
			}
			if !strings.Contains(strings.Join(anyStrings(record.NonClaims), "\n"), boundaryNonClaim) {
				t.Fatalf("Build() nonClaims=%#v, want caller-declaration boundary", record.NonClaims)
			}
		})
	}
}

func TestBuildRejectsVerificationSoundingLegacyStatuses(t *testing.T) {
	for _, status := range []string{"matched", "mismatched", "not_comparable", "not_run"} {
		t.Run(status, func(t *testing.T) {
			input := validMigrationParityInput()
			input["parityRecords"].([]any)[0].(map[string]any)["status"] = status

			_, _, err := Build(input)
			if err == nil {
				t.Fatal("Build() admitted legacy status that implies native verification")
			}
		})
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(string))
	}
	return result
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
				"status":             "caller_declared_match",
				"targetId":           "proofkit.test.target",
			},
		},
		"nonClaims": []any{"Migration parity test input is not rollout proof."},
	}
}
