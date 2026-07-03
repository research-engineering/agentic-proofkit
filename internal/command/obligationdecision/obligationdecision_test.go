package obligationdecision

import (
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

func TestBuildAdmitsSatisfiedBlockingObligationsAndRejectsMissingReceipt(t *testing.T) {
	result, err := Build(validObligationDecisionInput("satisfied", "not_applicable"))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", result.ExitCode, result.Report.State)
	}

	result, err = Build(validObligationDecisionInput("satisfied", "missing_receipt"))
	if err != nil {
		t.Fatalf("Build() missing receipt error=%v", err)
	}
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("Build() accepted blocking missing receipt: exit=%d state=%s", result.ExitCode, result.Report.State)
	}
	if len(result.BlockingUnsatisfiedObligationIDs) != 1 || result.BlockingUnsatisfiedObligationIDs[0] != "proofkit.obligation.two" {
		t.Fatalf("blocking unsatisfied=%#v, want second obligation", result.BlockingUnsatisfiedObligationIDs)
	}
}

func TestBuildAdmitsEveryProofVocabularyObligationDecisionState(t *testing.T) {
	for _, state := range proofvocab.ObligationDecisionStates() {
		t.Run(state, func(t *testing.T) {
			_, err := Build(validObligationDecisionInput(state, "not_applicable"))
			if err != nil {
				t.Fatalf("Build() rejected owner obligation decision state %q: %v", state, err)
			}
		})
	}
}

func TestBuildAdmitsEveryProofVocabularyObligationClass(t *testing.T) {
	for _, class := range proofvocab.ObligationClasses() {
		t.Run(class, func(t *testing.T) {
			input := validObligationDecisionInput("satisfied", "not_applicable")
			obligation := input["obligations"].([]any)[0].(map[string]any)
			obligation["obligationClass"] = class

			if _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner obligation class %q: %v", class, err)
			}
		})
	}
}

func TestBuildRejectsUnknownObligationDecisionState(t *testing.T) {
	_, err := Build(validObligationDecisionInput("invented_state", "not_applicable"))
	if err == nil {
		t.Fatalf("Build() accepted unknown obligation decision state")
	}
}

func validObligationDecisionInput(firstState string, secondState string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"decisionId":    "proofkit.test.decision",
		"nonClaims":     []any{"Synthetic obligation input does not approve merge."},
		"obligations": []any{
			validObligation("proofkit.obligation.one", "REQ-PROOFKIT-001", firstState),
			validObligation("proofkit.obligation.two", "REQ-PROOFKIT-002", secondState),
		},
	}
}

func validObligation(obligationID string, requirementID string, state string) map[string]any {
	return map[string]any{
		"candidateStates": []any{state},
		"evidenceRefs":    []any{"artifacts/proofkit/evidence.json"},
		"nonClaims":       []any{"Synthetic obligation is caller-owned."},
		"obligationClass": "blocking",
		"obligationId":    obligationID,
		"owner":           "proofkit.test",
		"proofRouteRef":   "proofkit.route.local",
		"reason":          "Synthetic test obligation.",
		"requirementId":   requirementID,
	}
}
