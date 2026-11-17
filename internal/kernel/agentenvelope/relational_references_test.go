package agentenvelope

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestRelationalExternalReferenceIdentitySurvivesFinalSerialization(t *testing.T) {
	for _, length := range []int{511, 512, 513} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			refs := []any{strings.Repeat("x", length-1) + "a", strings.Repeat("x", length-1) + "b"}
			input := referenceIdentityInput(nil, nil, nil, refs)
			input.BlockedPreconditions = []map[string]any{{"preconditionId": "blocked", "evidenceRefs": refs}}
			input.ClarificationQuestion = []map[string]any{{"questionId": "clarify", "evidenceRefs": refs}}
			input.Commands = []map[string]any{{"commandId": "command", "evidenceRefs": refs}}
			input.ContextRefs = []map[string]any{{"refId": "context", "evidenceRefs": refs}}
			input.Omitted = []map[string]any{{"omissionId": "omission", "omittedCount": 0, "evidenceRefs": refs}}
			input.ReceiptRefs = []map[string]any{{"receiptRefId": "receipt", "evidenceRefs": refs}}
			input.RouteQuestions = []map[string]any{{"questionId": "route", "evidenceRefs": refs}}
			input.ActionPlan[0]["instruction"] = strings.Repeat("d", 513)
			packet := Build(input)
			encoded, err := json.Marshal(packet)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"actionPlan", "blockedPreconditions", "clarificationQuestions", "commands", "contextRefs", "omitted", "receiptRefs", "routeQuestions"} {
				got := decoded[key].([]any)[0].(map[string]any)["evidenceRefs"].([]any)
				if len(got) != 2 || got[0] != refs[0] || got[1] != refs[1] {
					t.Errorf("%s lost external reference identity at length %d", key, length)
				}
			}
			action := packet["actionPlan"].([]any)[0].(map[string]any)
			if action["instruction"] == input.ActionPlan[0]["instruction"] {
				t.Error("descriptive prose escaped its scalar bound")
			}
			cost := packet["costContract"].(map[string]any)
			if cost["omittedEdgeCount"] != 0 || cost["prunedLocalReferenceCount"] != 0 || cost["referenceClosurePreserved"] != true {
				t.Error("safe external references unexpectedly degraded guidance")
			}
		})
	}
}

func TestRelationalExternalReferencesRetainPrivacyAndItemBounds(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A", 36)
	for _, unsafe := range []string{secret, "external\u2028ref", "external\u2029ref", "external\xffref"} {
		input := referenceIdentityInput(nil, nil, nil, []any{unsafe})
		packet := Build(input)
		assertAnyStrings(t, packet["actionPlan"].([]any)[0].(map[string]any)["evidenceRefs"], nil)
		assertIdentityDegraded(t, packet, 1, 1)
		assertEnvelopeDoesNotContain(t, packet, secret)
	}
	first, second := strings.Repeat("r", 512)+"a", strings.Repeat("r", 512)+"b"
	input := referenceIdentityInput(nil, nil, nil, []any{first, second})
	input.Bounds = map[string]any{"maxActionEvidenceRefs": 1}
	packet := Build(input)
	assertAnyStrings(t, packet["actionPlan"].([]any)[0].(map[string]any)["evidenceRefs"], []string{first})
	assertOmission(t, packet, "proofkit.agent-envelope.omitted.actionEvidenceRefs", 1)
}

func TestRelationalExternalReferencesKeepAllPrivacyClasses(t *testing.T) {
	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		t.Run(fixture.Name, func(t *testing.T) {
			packet := Build(referenceIdentityInput(nil, nil, nil, []any{fixture.Input}))
			assertAnyStrings(t, packet["actionPlan"].([]any)[0].(map[string]any)["evidenceRefs"], nil)
			assertIdentityDegraded(t, packet, 1, 1)
			for _, needle := range fixture.SensitiveNeedles {
				assertEnvelopeDoesNotContain(t, packet, needle)
			}
		})
	}
}

func TestRelationalOmissionsCountRecordRolesNotIDSpelling(t *testing.T) {
	for _, same := range []bool{false, true} {
		for _, metadata := range []string{"fallback", "binding", "both"} {
			t.Run(fmt.Sprintf("same=%t/%s", same, metadata), func(t *testing.T) {
				contextID, commandID := "context.rejected", "command.missing"
				if same {
					commandID = contextID
				}
				input := Input{ContextRefs: []map[string]any{{"refId": contextID, "ref": "unsafe\u2028value"}}}
				if metadata != "binding" {
					input.CallerDisplayFallbackCommandIDs = []string{commandID, commandID}
				}
				if metadata != "fallback" {
					input.OperandBindings = []OperandBinding{{CommandID: commandID}, {CommandID: commandID}}
				}
				packet := Build(input)
				assertOmission(t, packet, "proofkit.agent-envelope.omitted.unsafeStructuralOperand", 2)
				if packet["costContract"].(map[string]any)["omittedEdgeCount"] != 2 {
					t.Error("two record-role losses must count twice")
				}
			})
		}
	}
}

func TestRelationalOmissionsKeepIdentityAndMetadataCoalescing(t *testing.T) {
	id := strings.Repeat("a", 257)
	if _, admitted := losslessLocalIdentity(id); admitted {
		t.Fatal("fixture must exceed the stable identity limit")
	}
	for _, role := range []string{"command", "context", "receipt"} {
		t.Run(role, func(t *testing.T) {
			input := Input{OperandBindings: []OperandBinding{{CommandID: id}, {CommandID: id}}}
			switch role {
			case "command":
				input.Commands = []map[string]any{{"commandId": id}}
			case "context":
				input.ContextRefs = []map[string]any{{"refId": id}}
			case "receipt":
				input.ReceiptRefs = []map[string]any{{"receiptRefId": id}}
			}
			want := 2
			if role == "command" {
				want = 1
			}
			if got := Build(input)["costContract"].(map[string]any)["omittedEdgeCount"]; got != want {
				t.Errorf("omission count=%v want=%d", got, want)
			}
		})
	}
	input := Input{
		Commands:               []map[string]any{{"commandId": id}},
		ContextReferenceFields: []ContextReferenceField{{ContextRefID: id, Field: "ref"}, {ContextRefID: id, Field: "path"}},
	}
	if got := Build(input)["costContract"].(map[string]any)["omittedEdgeCount"]; got != 2 {
		t.Errorf("command rejection suppressed context metadata omission: %v", got)
	}
	for _, crossDomain := range []bool{false, true} {
		input := Input{
			Commands:                        []map[string]any{{"commandId": "shared"}},
			OperandBindings:                 []OperandBinding{{CommandID: "shared"}, {CommandID: "shared"}},
			CallerDisplayFallbackCommandIDs: []string{"shared", "shared"},
		}
		if crossDomain {
			input.ContextRefs = []map[string]any{{"refId": "shared"}}
			input.ContextReferenceFields = []ContextReferenceField{{ContextRefID: "shared", Field: "ref"}}
		} else {
			input.Commands = append(input.Commands, map[string]any{"commandId": "shared"})
		}
		packet := Build(input)
		assertOmission(t, packet, "proofkit.agent-envelope.omitted.ambiguousLocalIdentity", 1)
		if packet["costContract"].(map[string]any)["omittedEdgeCount"] != 1 {
			t.Error("ambiguous target was recounted through metadata")
		}
	}
}
