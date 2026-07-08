package receiptproduceradmission

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildAcceptsMergeSatisfyingProducerReceipt(t *testing.T) {
	record, exitCode, err := Build(validAdmission())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s", exitCode, record.State)
	}
}

func TestBuildRejectsAdvisoryProducerForMergeSatisfyingReceipt(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.016058221490407979556173242304898277468063189448256779462558039961547903134881")
	input := validAdmission()
	producer := input["producers"].([]any)[0].(map[string]any)
	producer["admissionLevel"] = "advisory"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	for _, rule := range record.RuleResults {
		if rule.RuleID != "proofkit.receipt-producer-admission.receipts" {
			continue
		}
		for _, diagnostic := range rule.Diagnostics {
			if text, ok := diagnostic.Value.(string); ok && strings.Contains(text, "advisory producer") {
				return
			}
		}
	}
	t.Fatalf("receipt diagnostics did not explain advisory producer failure: %#v", record.RuleResults)
}

func TestBuildRejectsMergeSatisfyingReceiptWithoutProvenance(t *testing.T) {
	input := validAdmission()
	receipt := input["receipts"].([]any)[0].(map[string]any)
	delete(receipt, "provenanceRef")

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	for _, rule := range record.RuleResults {
		if rule.RuleID != "proofkit.receipt-producer-admission.receipts" {
			continue
		}
		for _, diagnostic := range rule.Diagnostics {
			if text, ok := diagnostic.Value.(string); ok && strings.Contains(text, "without provenanceRef") {
				return
			}
		}
	}
	t.Fatalf("receipt diagnostics did not explain missing provenance: %#v", record.RuleResults)
}

func TestBuildRejectsUnknownReceiptField(t *testing.T) {
	input := validAdmission()
	receipt := input["receipts"].([]any)[0].(map[string]any)
	receipt["ambientTrust"] = true

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Build() error=%v, want unsupported field", err)
	}
}

func TestBuildRejectsUnknownReceiptStatus(t *testing.T) {
	input := validAdmission()
	receipt := input["receipts"].([]any)[0].(map[string]any)
	receipt["status"] = "cancelled"

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "receipt producer admission receipt.status must be one of") {
		t.Fatalf("Build() error=%v, want receipt status vocabulary rejection", err)
	}
}

func TestBuildAdmitsEveryProofVocabularyReceiptStatus(t *testing.T) {
	for _, status := range proofvocab.ReceiptStatuses() {
		t.Run(status, func(t *testing.T) {
			input := validAdmission()
			receipt := input["receipts"].([]any)[0].(map[string]any)
			receipt["status"] = status
			receipt["satisfiesMergeObligation"] = status == "passed"

			if _, _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner receipt status %q: %v", status, err)
			}
		})
	}
}

func TestEvaluateProjectsAdmittedReceiptLinkageFacts(t *testing.T) {
	projection, record, exitCode, err := Evaluate(validAdmission())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Evaluate() exit=%d state=%s, want passed", exitCode, record.State)
	}
	if projection.PolicyID != "proofkit.test.producer_policy" {
		t.Fatalf("PolicyID=%q, want proofkit.test.producer_policy", projection.PolicyID)
	}
	if len(projection.Receipts) != 1 {
		t.Fatalf("Receipts=%#v, want one receipt projection", projection.Receipts)
	}
	receipt := projection.Receipts[0]
	if receipt.ReceiptID != "receipt.producer.one" ||
		receipt.ProducerID != "github.actions.package" ||
		receipt.ReceiptKind != "proofkit.package-gate" ||
		receipt.EnvironmentClass != "local-go" ||
		receipt.SubjectRef != "proofkit.go-test" ||
		receipt.Status != "passed" ||
		receipt.EvidenceRef != "artifacts/test/report.json" ||
		len(receipt.ArtifactRefs) != 1 ||
		receipt.ArtifactRefs[0] != "artifacts/test/report.json" ||
		receipt.ProvenanceRef == nil ||
		*receipt.ProvenanceRef != "artifacts/test/provenance.json" ||
		!receipt.SatisfiesMergeObligation {
		t.Fatalf("Receipt projection=%#v, want admitted merge-satisfying receipt facts", receipt)
	}
}

func validAdmission() map[string]any {
	return map[string]any{
		"schemaVersion":      json.Number("1"),
		"policyId":           "proofkit.test.producer_policy",
		"environmentClasses": []any{"local-go"},
		"receiptKinds":       []any{"proofkit.package-gate"},
		"nonClaims":          []any{"Producer admission test input does not authenticate producers."},
		"producers": []any{
			map[string]any{
				"admissionLevel":     "merge_satisfying",
				"environmentClasses": []any{"local-go"},
				"evidenceRefs":       []any{"docs/test.md"},
				"nonClaim":           "Synthetic producer only admits this test receipt.",
				"owner":              "proofkit.test",
				"producerId":         "github.actions.package",
				"receiptKinds":       []any{"proofkit.package-gate"},
			},
		},
		"receipts": []any{
			map[string]any{
				"artifactRefs":             []any{"artifacts/test/report.json"},
				"environmentClass":         "local-go",
				"evidenceRef":              "artifacts/test/report.json",
				"nonClaim":                 "Synthetic producer receipt.",
				"producerId":               "github.actions.package",
				"provenanceRef":            "artifacts/test/provenance.json",
				"receiptId":                "receipt.producer.one",
				"receiptKind":              "proofkit.package-gate",
				"satisfiesMergeObligation": true,
				"status":                   "passed",
				"subjectRef":               "proofkit.go-test",
			},
		},
	}
}
