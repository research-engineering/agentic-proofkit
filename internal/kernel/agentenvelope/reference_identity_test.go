package agentenvelope

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBuildRejectsDuplicateAndCrossDomainLocalIdentities(t *testing.T) {
	sharedID := "proofkit.shared.identity"
	tests := []struct {
		name     string
		commands []map[string]any
		contexts []map[string]any
		receipts []map[string]any
	}{
		{name: "duplicate commands", commands: []map[string]any{{"commandId": sharedID}, {"commandId": sharedID}}},
		{name: "duplicate contexts", contexts: []map[string]any{{"refId": sharedID}, {"refId": sharedID}}},
		{name: "duplicate receipts", receipts: []map[string]any{{"receiptRefId": sharedID}, {"receiptRefId": sharedID}}},
		{name: "command context collision", commands: []map[string]any{{"commandId": sharedID}}, contexts: []map[string]any{{"refId": sharedID}}},
		{name: "command receipt collision", commands: []map[string]any{{"commandId": sharedID}}, receipts: []map[string]any{{"receiptRefId": sharedID}}},
		{name: "context receipt collision", contexts: []map[string]any{{"refId": sharedID}}, receipts: []map[string]any{{"receiptRefId": sharedID}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := Build(referenceIdentityInput(test.commands, test.contexts, test.receipts, []any{sharedID}))

			assertLocalIdentityAbsent(t, envelope, sharedID)
			assertIdentityDegraded(t, envelope, 1, 1)
			assertOmission(t, envelope, "proofkit.agent-envelope.omitted.ambiguousLocalIdentity", 1)
		})
	}
}

func TestBuildPrunesAmbiguousIdentityFromEveryReferenceContainer(t *testing.T) {
	sharedID := "proofkit.shared.identity"
	referenced := func(idKey string, id string) map[string]any {
		return map[string]any{
			idKey:          id,
			"commandIds":   []any{sharedID},
			"evidenceRefs": []any{sharedID},
		}
	}
	input := referenceIdentityInput(
		[]map[string]any{referenced("commandId", "proofkit.command.unique")},
		[]map[string]any{
			{"refId": sharedID},
			{"refId": sharedID},
			referenced("refId", "proofkit.context.unique"),
		},
		[]map[string]any{referenced("receiptRefId", "proofkit.receipt.unique")},
		nil,
	)
	input.ActionPlan = []map[string]any{referenced("stepId", "proofkit.step.unique")}
	input.BlockedPreconditions = []map[string]any{referenced("preconditionId", "proofkit.precondition.unique")}
	input.ClarificationQuestion = []map[string]any{referenced("questionId", "proofkit.clarification.unique")}
	input.RouteQuestions = []map[string]any{referenced("questionId", "proofkit.route.unique")}
	input.Omitted = []map[string]any{
		{
			"commandIds":   []any{sharedID},
			"evidenceRefs": []any{sharedID},
			"omissionId":   "proofkit.omission.unique",
			"omittedCount": 0,
		},
	}

	envelope := Build(input)
	assertLocalIdentityAbsent(t, envelope, sharedID)
	assertIdentityDegraded(t, envelope, 1, 16)
	assertOmission(t, envelope, "proofkit.agent-envelope.omitted.ambiguousLocalIdentity", 1)
}

func TestBuildOmitsUnsafeTargetsAndReferencesBeforeDisplaySanitization(t *testing.T) {
	secret := "ghp_FAKEFAKE1234567890"
	control := "proofkit.control\u202evalue"
	invalidShape := "proofkit invalid identity"
	input := referenceIdentityInput(
		[]map[string]any{{"commandId": secret}},
		[]map[string]any{{"refId": control}},
		[]map[string]any{{"receiptRefId": invalidShape}},
		[]any{secret, control, invalidShape, "proofkit.external.safe"},
	)
	input.ActionPlan[0]["commandIds"] = []any{secret, control, invalidShape, "proofkit.command.missing"}

	envelope := Build(input)
	encoded, err := stablejson.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	for _, forbidden := range []string{secret, control, invalidShape, "<redacted-diagnostic-value>"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("envelope retained unsafe identity %q:\n%s", forbidden, encoded)
		}
	}
	action := envelope["actionPlan"].([]any)[0].(map[string]any)
	assertAnyStrings(t, action["evidenceRefs"], []string{"proofkit.external.safe"})
	assertAnyStrings(t, action["commandIds"], nil)
	assertIdentityDegraded(t, envelope, 3, 7)
	assertOmission(t, envelope, "proofkit.agent-envelope.omitted.unsafeLocalIdentity", 3)
}

func TestBuildCountsStandaloneUnsafeReferenceOmissions(t *testing.T) {
	secret := "ghp_FAKEFAKE1234567890"
	input := referenceIdentityInput(nil, nil, nil, []any{secret})
	input.ActionPlan[0]["commandIds"] = []any{secret}

	envelope := Build(input)
	assertIdentityDegraded(t, envelope, 2, 2)
	assertOmission(t, envelope, "proofkit.agent-envelope.omitted.unsafeLocalReference", 2)
}

func TestBuildPreservesUniqueLocalAndSafeExternalReferences(t *testing.T) {
	input := referenceIdentityInput(
		[]map[string]any{{"commandId": "proofkit.command.unique"}},
		[]map[string]any{{"refId": "proofkit.context.unique"}},
		[]map[string]any{{"receiptRefId": "proofkit.receipt.unique"}},
		[]any{"proofkit.command.unique", "proofkit.context.unique", "proofkit.receipt.unique", "https://example.test/evidence"},
	)
	input.ActionPlan[0]["commandIds"] = []any{"proofkit.command.unique"}

	envelope := Build(input)
	action := envelope["actionPlan"].([]any)[0].(map[string]any)
	assertAnyStrings(t, action["evidenceRefs"], []string{
		"proofkit.command.unique",
		"proofkit.context.unique",
		"proofkit.receipt.unique",
		"https://example.test/evidence",
	})
	assertAnyStrings(t, action["commandIds"], []string{"proofkit.command.unique"})
	cost := envelope["costContract"].(map[string]any)
	if cost["referenceClosurePreserved"] != true || cost["prunedLocalReferenceCount"] != 0 || cost["omittedEdgeCount"] != 0 {
		t.Fatalf("unique reference cost contract = %#v", cost)
	}
	if bounds := envelope["bounds"].(map[string]any); bounds["truncated"] == true {
		t.Fatalf("unique reference envelope was marked truncated: %#v", bounds)
	}
}

func referenceIdentityInput(commands []map[string]any, contexts []map[string]any, receipts []map[string]any, evidenceRefs []any) Input {
	return Input{
		ActionPlan: []map[string]any{
			{
				"commandIds":   []any{},
				"evidenceRefs": evidenceRefs,
				"stepId":       "proofkit.step.reference-identity",
			},
		},
		Commands:    commands,
		ContextRefs: contexts,
		EnvelopeID:  "proofkit.envelope.reference-identity",
		ReceiptRefs: receipts,
		SourceReport: map[string]any{
			"reportId":   "proofkit.report.reference-identity",
			"reportKind": "proofkit.test",
			"state":      "passed",
		},
	}
}

func assertLocalIdentityAbsent(t *testing.T, envelope map[string]any, identity string) {
	t.Helper()
	for _, field := range []struct {
		name string
		key  string
	}{{"commands", "commandId"}, {"contextRefs", "refId"}, {"receiptRefs", "receiptRefId"}} {
		for _, raw := range envelope[field.name].([]any) {
			if raw.(map[string]any)[field.key] == identity {
				t.Fatalf("%s retained ambiguous identity %q: %#v", field.name, identity, envelope[field.name])
			}
		}
	}
	encoded, err := stablejson.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if strings.Contains(string(encoded), identity) {
		t.Fatalf("envelope retained ambiguous identity %q:\n%s", identity, encoded)
	}
}

func assertIdentityDegraded(t *testing.T, envelope map[string]any, omittedEdges int, prunedReferences int) {
	t.Helper()
	cost := envelope["costContract"].(map[string]any)
	if cost["referenceClosurePreserved"] != false || cost["omittedEdgeCount"] != omittedEdges || cost["prunedLocalReferenceCount"] != prunedReferences {
		t.Fatalf("identity-degraded cost contract = %#v, want omitted=%d pruned=%d", cost, omittedEdges, prunedReferences)
	}
	bounds := envelope["bounds"].(map[string]any)
	if bounds["truncated"] != true || bounds["referenceClosurePreserved"] != false {
		t.Fatalf("identity-degraded bounds = %#v", bounds)
	}
}

func assertOmission(t *testing.T, envelope map[string]any, omissionID string, count int) {
	t.Helper()
	for _, raw := range envelope["omitted"].([]any) {
		omission := raw.(map[string]any)
		if omission["omissionId"] == omissionID {
			if omission["omittedCount"] != count {
				t.Fatalf("%s count = %v, want %d", omissionID, omission["omittedCount"], count)
			}
			return
		}
	}
	t.Fatalf("omission %s is absent: %#v", omissionID, envelope["omitted"])
}

func assertAnyStrings(t *testing.T, raw any, expected []string) {
	t.Helper()
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("value type = %T, want []any", raw)
	}
	if len(values) != len(expected) {
		t.Fatalf("values = %#v, want %#v", values, expected)
	}
	for index, expectedValue := range expected {
		if values[index] != expectedValue {
			t.Fatalf("values[%d] = %v, want %s", index, values[index], expectedValue)
		}
	}
}
