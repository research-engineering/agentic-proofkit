package receipttrustclass

import (
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

func TestBuildAdmitsTrustedReceiptAndRejectsMissingProvenance(t *testing.T) {
	input := validReceiptTrustClassInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input = validReceiptTrustClassInput()
	input["obligationReceipts"].([]any)[0].(map[string]any)["provenanceRef"] = nil
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(mutated) error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(mutated) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func TestBuildAdmitsEveryProofVocabularyReceiptStatus(t *testing.T) {
	for _, status := range proofvocab.ReceiptStatuses() {
		t.Run(status, func(t *testing.T) {
			input := validReceiptTrustClassInput()
			trustClass := input["trustClasses"].([]any)[0].(map[string]any)
			trustClass["allowedReceiptStatuses"] = []any{status}
			receipt := input["obligationReceipts"].([]any)[0].(map[string]any)
			receipt["receiptStatus"] = status

			if _, _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner receipt status %q: %v", status, err)
			}
		})
	}
}

func TestBuildAdmitsEveryProofVocabularyMergeSatisfactionClass(t *testing.T) {
	for _, class := range proofvocab.MergeSatisfactionClasses() {
		t.Run(class, func(t *testing.T) {
			input := validReceiptTrustClassInput()
			trustClass := input["trustClasses"].([]any)[0].(map[string]any)
			trustClass["allowedProducerAdmissionLevels"] = []any{class}
			receipt := input["obligationReceipts"].([]any)[0].(map[string]any)
			receipt["producerAdmissionClass"] = class

			if _, _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner merge-satisfaction class %q: %v", class, err)
			}
		})
	}
}

func validReceiptTrustClassInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"policyId":      "proofkit.test.trust_policy",
		"trustClasses": []any{
			map[string]any{
				"trustClassId":                   "proofkit.test.trusted",
				"rank":                           json.Number("2"),
				"allowedProducerAdmissionLevels": []any{"merge_satisfying"},
				"allowedReceiptStatuses":         []any{"passed"},
				"requiresArtifactRefs":           true,
				"requiresProvenanceRef":          true,
				"nonClaims":                      []any{"Trust class test fixture does not authenticate producers."},
			},
		},
		"proofClasses": []any{
			map[string]any{
				"proofClassId":              "proofkit.test.proof_class",
				"minimumTrustClassId":       "proofkit.test.trusted",
				"allowedReceiptKinds":       []any{"proofkit.package-gate"},
				"allowedEnvironmentClasses": []any{"local-go"},
				"owner":                     "proofkit.test.owner",
				"riskClass":                 "merge_gate",
				"rationale":                 "test merge-satisfying receipts require provenance",
				"nonClaims":                 []any{"Proof class test fixture is not merge approval."},
			},
		},
		"obligationReceipts": []any{
			map[string]any{
				"artifactRefs":           []any{"artifacts/proofkit/receipt.json"},
				"environmentClass":       "local-go",
				"evidenceRefs":           []any{"artifacts/proofkit/evidence.json"},
				"nonClaims":              []any{"Receipt trust test input does not prove native command success."},
				"obligationId":           "proofkit.test.obligation",
				"producerAdmissionClass": "merge_satisfying",
				"proofClassId":           "proofkit.test.proof_class",
				"proofRouteRef":          "proofkit.test.route",
				"provenanceRef":          "artifacts/proofkit/provenance.json",
				"receiptId":              "proofkit.test.receipt",
				"receiptKind":            "proofkit.package-gate",
				"receiptStatus":          "passed",
				"requirementId":          "REQ-PROOFKIT-TEST-001",
				"trustClassId":           "proofkit.test.trusted",
			},
		},
		"nonClaims": []any{"Receipt trust-class test input does not approve merge."},
	}
}
