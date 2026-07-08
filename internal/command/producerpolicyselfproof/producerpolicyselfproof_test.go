package producerpolicyselfproof

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildRejectsPolicyChangeProvedByNewlyAdmittedProducerTuple(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.051973025282364233365946493539636279354221690599943144823854134459401810936427")
	record, exitCode, err := Build(validProducerPolicySelfProofInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	input := validProducerPolicySelfProofInput()
	receipt := input["mergeObligationReceiptRefs"].([]any)[0].(map[string]any)
	receipt["producerId"] = "producer.new"
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() newly admitted tuple error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "uses newly admitted producer tuple") {
		t.Fatalf("Build() accepted self-proving producer policy change: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func TestBuildRejectsUnknownReceiptStatus(t *testing.T) {
	input := validProducerPolicySelfProofInput()
	receipt := input["mergeObligationReceiptRefs"].([]any)[0].(map[string]any)
	receipt["receiptStatus"] = "cancelled"

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "producer policy self-proof receipt.receiptStatus must be one of") {
		t.Fatalf("Build() error=%v, want receipt status vocabulary rejection", err)
	}
}

func TestBuildAdmitsEveryProofVocabularyReceiptStatus(t *testing.T) {
	for _, status := range proofvocab.ReceiptStatuses() {
		t.Run(status, func(t *testing.T) {
			input := validProducerPolicySelfProofInput()
			receipt := input["mergeObligationReceiptRefs"].([]any)[0].(map[string]any)
			receipt["receiptStatus"] = status
			receipt["satisfiesMergeObligation"] = status == "passed"

			if _, _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner receipt status %q: %v", status, err)
			}
		})
	}
}

func validProducerPolicySelfProofInput() map[string]any {
	return map[string]any{
		"schemaVersion":        json.Number("1"),
		"guardId":              "proofkit.test.producer-policy-self-proof",
		"policyId":             "proofkit.test.producer-policy",
		"policyOwner":          "proofkit",
		"policySurfaceRefs":    []any{"proofkit/receipt-producer-policy.json"},
		"baselinePolicyDigest": proofPolicyDigest(),
		"proposedPolicyDigest": "sha256:" + strings.Repeat("b", 64),
		"policyChangeDigest":   "sha256:" + strings.Repeat("c", 64),
		"policyChangeId":       "proofkit.test.policy-change",
		"nonClaimRefs":         []any{},
		"nonClaims":            []any{},
		"admissionChanges":     []any{producerAdmissionChange()},
		"mergeObligationReceiptRefs": []any{
			producerMergeObligationReceipt(),
		},
	}
}

func producerAdmissionChange() map[string]any {
	return map[string]any{
		"changeId":                 "proofkit.test.change",
		"changeKind":               "promote_to_merge_satisfying",
		"producerId":               "producer.new",
		"producerClass":            "github-actions",
		"proofClass":               "ci",
		"receiptKind":              "proof",
		"environmentClass":         "github-actions",
		"provenanceRuleRef":        "docs/release-process.md",
		"artifactRetentionRuleRef": "docs/release-process.md",
		"fromAdmissionLevel":       "advisory",
		"toAdmissionLevel":         "merge_satisfying",
		"evidenceRefs":             []any{"docs/release-process.md"},
		"nonClaimRefs":             []any{},
		"nonClaim":                 "The policy change test does not authenticate producers.",
	}
}

func producerMergeObligationReceipt() map[string]any {
	return map[string]any{
		"receiptId":                "proofkit.test.receipt",
		"producerId":               "producer.existing",
		"producerClass":            "github-actions",
		"proofClass":               "ci",
		"receiptKind":              "proof",
		"environmentClass":         "github-actions",
		"provenanceRuleRef":        "docs/release-process.md",
		"artifactRetentionRuleRef": "docs/release-process.md",
		"producerAdmissionClass":   "merge_satisfying",
		"receiptStatus":            "passed",
		"proofReceiptRef":          "artifacts/proofkit/receipt.json",
		"proofReceiptDigest":       "sha256:" + strings.Repeat("d", 64),
		"evidenceRef":              "artifacts/proofkit/receipt.json",
		"nonClaimRefs":             []any{},
		"nonClaim":                 "The receipt ref test does not prove producer identity.",
		"satisfiesMergeObligation": true,
		"usedForPolicyChangeId":    "proofkit.test.policy-change",
	}
}

func proofPolicyDigest() string {
	return "sha256:" + strings.Repeat("a", 64)
}
