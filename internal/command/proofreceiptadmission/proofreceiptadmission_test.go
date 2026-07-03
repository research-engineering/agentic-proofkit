package proofreceiptadmission

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

func TestBuildAdmitsAdvisoryReceiptAndRejectsMergeSatisfyingWithoutProvenance(t *testing.T) {
	record, exitCode, err := Build(validProofReceiptInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	input := validProofReceiptInput()
	receipt := input["receipts"].([]any)[0].(map[string]any)
	receipt["producerAdmissionClass"] = "merge_satisfying"
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() merge_satisfying error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "without provenanceRef") {
		t.Fatalf("Build() accepted merge_satisfying receipt without provenance: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func TestBuildRejectsUnknownReceiptStatus(t *testing.T) {
	input := validProofReceiptInput()
	receipt := input["receipts"].([]any)[0].(map[string]any)
	receipt["status"] = "cancelled"

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "proof receipt admission receipt.status must be one of") {
		t.Fatalf("Build() error=%v, want receipt status vocabulary rejection", err)
	}
}

func TestBuildAdmitsEveryProofVocabularyReceiptStatus(t *testing.T) {
	for _, status := range proofvocab.ReceiptStatuses() {
		t.Run(status, func(t *testing.T) {
			input := validProofReceiptInput()
			receipt := input["receipts"].([]any)[0].(map[string]any)
			receipt["status"] = status
			receipt["exitCode"] = proofReceiptExitCode(status)
			if status == "blocked" || status == "not_run" {
				receipt["nonClaims"] = []any{"Synthetic blocked receipt does not prove command execution."}
			}

			if _, _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner receipt status %q: %v", status, err)
			}
		})
	}
}

func validProofReceiptInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"receiptSetId":  "proofkit.test.receipt-set",
		"nonClaims":     []any{},
		"receipts": []any{
			map[string]any{
				"artifactRefs": []any{
					map[string]any{"kind": "report", "path": "artifacts/proofkit/report.json", "sha256": testDigest("artifact")},
				},
				"commandDigest":          testDigest("command"),
				"dependencyDigest":       nil,
				"environmentClass":       "local-go",
				"environmentDigest":      testDigest("environment"),
				"evidenceRefs":           []any{"artifacts/proofkit/evidence.json"},
				"exitCode":               json.Number("0"),
				"finishedAt":             "2026-06-26T10:00:01Z",
				"lockfileDigest":         nil,
				"nonClaims":              []any{},
				"preconditionDigest":     testDigest("precondition"),
				"producerAdmissionClass": "advisory",
				"producerId":             "producer.local",
				"proofBindingDigest":     testDigest("binding"),
				"proofPlanId":            "proofkit.test.plan",
				"provenanceRef":          nil,
				"receiptId":              "proofkit.test.receipt",
				"receiptKind":            "unit-test",
				"runnerClass":            "local",
				"runnerIdentity":         "runner.local",
				"sourceRevision":         "commit",
				"startedAt":              "2026-06-26T10:00:00Z",
				"status":                 "passed",
				"toolchainDigest":        testDigest("toolchain"),
				"witnessSelectorDigest":  testDigest("witness-selector"),
				"witnessSelectors":       []any{"proofkit.test.witness"},
			},
		},
	}
}

func proofReceiptExitCode(status string) any {
	switch status {
	case "passed":
		return json.Number("0")
	case "failed":
		return json.Number("1")
	default:
		return nil
	}
}

func testDigest(seed string) string {
	hexDigits := "abcdef0123456789"
	return "sha256:" + strings.Repeat(hexDigits[len(seed)%len(hexDigits):len(seed)%len(hexDigits)+1], 64)
}
