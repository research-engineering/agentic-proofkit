package receiptcurrentnessscope

import (
	"encoding/json"
	"testing"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestBuildAdmitsCurrentScopedReceiptAndRejectsStaleDigest(t *testing.T) {
	input := validReceiptCurrentnessScopeInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input = validReceiptCurrentnessScopeInput()
	input["obligationReceipts"].([]any)[0].(map[string]any)["currentnessChecks"].([]any)[0].(map[string]any)["currentDigest"] = digestB
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(mutated) error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(mutated) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func validReceiptCurrentnessScopeInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"admissionId":   "proofkit.test.currentness",
		"obligationReceipts": []any{
			map[string]any{
				"obligationId":  "proofkit.test.obligation",
				"requirementId": "REQ-PROOFKIT-TEST-001",
				"proofRouteRef": "proofkit.test.route",
				"receiptId":     "proofkit.test.receipt",
				"owner":         "proofkit.test.owner",
				"reason":        "test receipt is current",
				"evidenceRefs":  []any{"artifacts/proofkit/receipt.json"},
				"currentnessChecks": []any{
					map[string]any{"checkId": "proofkit.test.current", "checkClass": "binding", "recordedDigest": digestA, "currentDigest": digestA, "evidenceRefs": []any{"proofkit/requirement-bindings.json"}, "nonClaims": []any{"Currentness test input does not read files."}},
				},
				"scopeChecks": []any{
					map[string]any{"checkId": "proofkit.test.scope", "scopeClass": "changed_files", "admissionState": "admitted_current_scope", "recordedScopeDigest": digestA, "currentScopeDigest": digestA, "reason": "same scope", "evidenceRefs": []any{"artifacts/proofkit/scope.json"}, "nonClaims": []any{"Scope test input does not compute changed files."}},
				},
				"nonClaims": []any{"Receipt currentness test input does not prove merge readiness."},
			},
		},
		"nonClaims": []any{"Receipt currentness-scope report test input is not merge proof."},
	}
}
