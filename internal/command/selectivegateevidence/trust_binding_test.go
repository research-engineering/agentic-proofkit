package selectivegateevidence

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/obligationdecision"
)

func TestTrustProjectionBindsEvaluatedReceiptFacts(t *testing.T) {
	for _, field := range []string{"receiptKind", "environmentClass", "producerAdmissionClass", "artifactRefs", "provenanceRef"} {
		t.Run(field, func(t *testing.T) {
			input := fullyBoundProjectionInput()
			assertProjectedDecision(t, input, "passed")
			trust := input["receiptTrustClassAdmission"].(map[string]any)
			receipt := trust["obligationReceipts"].([]any)[0].(map[string]any)
			switch field {
			case "receiptKind":
				receipt[field] = "proofkit.other-kind"
			case "environmentClass":
				receipt[field] = "remote-ci"
			case "producerAdmissionClass":
				receipt[field] = "advisory"
			case "artifactRefs":
				receipt[field] = []any{}
			case "provenanceRef":
				receipt[field] = "artifacts/other-provenance.json"
			}
			if _, err := ProjectObligationDecision(input); err == nil || !strings.Contains(err.Error(), field+" mismatch") {
				t.Fatalf("unbound %s accepted or wrong cause: %v", field, err)
			}
		})
	}
}

func TestTrustProjectionRejectsStaleMetadataAndPreservesPolicyDecisions(t *testing.T) {
	for _, field := range []string{"receiptKind", "environmentClass", "artifactRefs"} {
		t.Run(field, func(t *testing.T) {
			input := fullyBoundProjectionInput()
			evidence := input["evidence"].(map[string]any)
			producerInput := evidence["producerAdmission"].(map[string]any)
			producer := producerInput["producers"].([]any)[0].(map[string]any)
			trust := input["receiptTrustClassAdmission"].(map[string]any)
			trustReceipt := trust["obligationReceipts"].([]any)[0].(map[string]any)
			var changed any
			switch field {
			case "receiptKind":
				changed = "proofkit.other-kind"
				producerInput["receiptKinds"] = []any{changed}
				producer["receiptKinds"] = []any{changed}
			case "environmentClass":
				changed = "remote-ci"
				producerInput["environmentClasses"] = []any{changed}
				producer["environmentClasses"] = []any{changed}
			case "artifactRefs":
				changed = []any{}
				selectiveReceipt(evidence)[field] = changed
			}
			producerReceipt(evidence)[field] = changed
			if _, err := ProjectObligationDecision(input); err == nil || !strings.Contains(err.Error(), field+" mismatch") {
				t.Fatalf("stale trusted %s survived: %v", field, err)
			}
			trustReceipt[field] = changed
			assertProjectedDecision(t, input, "failed")
			proofClass := trust["proofClasses"].([]any)[0].(map[string]any)
			switch field {
			case "receiptKind":
				proofClass["allowedReceiptKinds"] = []any{changed}
			case "environmentClass":
				proofClass["allowedEnvironmentClasses"] = []any{changed}
			case "artifactRefs":
				trust["trustClasses"].([]any)[0].(map[string]any)["requiresArtifactRefs"] = false
			}
			assertProjectedDecision(t, input, "passed")
		})
	}
}

func TestTrustProjectionNeedsProducerFactsButKeepsEvidenceRolesDistinct(t *testing.T) {
	input := fullyBoundProjectionInput()
	trustReceipt := input["receiptTrustClassAdmission"].(map[string]any)["obligationReceipts"].([]any)[0].(map[string]any)
	trustReceipt["evidenceRefs"] = []any{"artifacts/independent-trust-check.json"}
	assertProjectedDecision(t, input, "passed")
	evidence := input["evidence"].(map[string]any)
	evidence["producerAdmission"] = nil
	evidence["evidenceClass"] = "advisory"
	if _, err := ProjectObligationDecision(input); err == nil || !strings.Contains(err.Error(), "requires admitted producer receipt") {
		t.Fatalf("unknown producer facts were trusted: %v", err)
	}
}

func fullyBoundProjectionInput() map[string]any {
	input := validProjectionInput()
	input["receiptCurrentnessScopeAdmission"] = validCurrentnessScopeAdmission()
	input["receiptTrustClassAdmission"] = validReceiptTrustAdmission()
	return input
}

func assertProjectedDecision(t *testing.T, input map[string]any, state string) {
	t.Helper()
	projected, err := ProjectObligationDecision(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := obligationdecision.Build(projected)
	if err != nil || result.Report.State != state || (result.ExitCode == 0) != (state == "passed") {
		t.Fatalf("final decision=%#v error=%v, want %s", result, err, state)
	}
}
