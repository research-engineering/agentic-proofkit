package nativeevidenceguidance

import (
	"strings"
	"testing"
)

func TestGuidanceRequiredWitnessCriterion(t *testing.T) {
	guidance, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	oracle := guidance.Slots[8]
	if oracle.SlotID != "oracle_rule" {
		t.Fatal("required-witness guidance moved away from the oracle owner")
	}
	for _, clause := range []string{
		"Select one stable rule ID and deterministic observation mapping.",
		"For a required-native-test claim",
		"derive a nonempty required witness set from admitted obligations, not just observed tests",
	} {
		t.Run(clause, func(t *testing.T) {
			if !strings.Contains(oracle.RequiredConsumerDecision, clause) {
				t.Fatalf("oracle decision omits %q", clause)
			}
		})
	}
	for _, clause := range []string{
		"Every admitted observation maps to exactly one verdict and the near-miss activates the intended rule.",
		"Before the ordinary verification route reports success",
		"require actual qualified execution outcomes for every required witness",
		"missing, unmatched, skipped, failed, unresolved or ambiguous outcomes cannot pass",
		"Owner-admitted not_applicable is a separate disposition, never a passed required witness",
	} {
		t.Run(clause, func(t *testing.T) {
			if !strings.Contains(oracle.CompletionCriterion, clause) {
				t.Fatalf("oracle completion omits %q", clause)
			}
		})
	}
}

func TestGuidanceReferenceRejectsReleased0194Content(t *testing.T) {
	// Exact reference emitted by the installed 0.19.4 carrier, not a fabricated hash.
	released := map[string]any{
		"commandId":     "native-evidence-guidance",
		"contentSha256": "sha256:366f2f37482506b8c94042dbd974469fceda79e2141b4faec61071893190b3ea",
		"guidanceId":    "proofkit.native-evidence-guidance.v1",
		"slotCount":     SlotCount,
	}
	if _, err := AdmitReference(released); err == nil {
		t.Fatal("released guidance reference silently acquired new content")
	}
	current, err := GuidanceReference()
	if err != nil {
		t.Fatal(err)
	}
	if current.GuidanceID != released["guidanceId"] || current.ContentSHA256 == released["contentSha256"] {
		t.Fatal("shape identity must remain stable while complete content identity changes")
	}
	if _, err := AdmitReference(current.JSONValue()); err != nil {
		t.Fatalf("fresh reference refused: %v", err)
	}
}
