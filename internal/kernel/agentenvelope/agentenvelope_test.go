package agentenvelope

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBuildSortsRefsAndCountsOmittedEdges(t *testing.T) {
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"reportId":   "proofkit.test.report",
			"reportKind": "proofkit.test",
			"state":      "passed",
		},
		ContextRefs: []map[string]any{
			{"refId": "ref.z"},
			{"refId": "ref.a"},
		},
		Commands: []map[string]any{
			{"commandId": "proofkit.z"},
			{"commandId": "proofkit.a"},
		},
		ReceiptRefs: []map[string]any{
			{"receiptRefId": "receipt.z"},
			{"receiptRefId": "receipt.a"},
		},
		Omitted: []map[string]any{
			{"omissionId": "omit.z", "omittedCount": 2},
			{"omissionId": "omit.a", "omittedCount": 3},
		},
	})

	assertFirstID(t, envelope["contextRefs"], "refId", "ref.a")
	assertFirstID(t, envelope["commands"], "commandId", "proofkit.a")
	assertFirstID(t, envelope["receiptRefs"], "receiptRefId", "receipt.a")
	assertFirstID(t, envelope["omitted"], "omissionId", "omit.a")
	cost := envelope["costContract"].(map[string]any)
	if cost["omittedEdgeCount"] != 5 || cost["stopReason"] != "wide_or_full_gate_required" {
		t.Fatalf("unexpected cost contract: %#v", cost)
	}
}

func TestBuildMarksFailedSourceAsBlockedPrecondition(t *testing.T) {
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"reportId":   "proofkit.test.report",
			"reportKind": "proofkit.test",
			"state":      "failed",
		},
	})
	cost := envelope["costContract"].(map[string]any)
	if cost["stopReason"] != "blocked_precondition" {
		t.Fatalf("stopReason=%v want blocked_precondition", cost["stopReason"])
	}
}

func TestBuildMarksOversizedBoundedEnvelopeAsWide(t *testing.T) {
	commands := make([]map[string]any, hardMaxCommandRefs+1)
	for index := range commands {
		commands[index] = map[string]any{"commandId": "proofkit.command." + string(rune('a'+index))}
	}
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"reportId":   "proofkit.test.report",
			"reportKind": "proofkit.test",
			"state":      "passed",
		},
		Bounds: map[string]any{
			"escalation":      "Caller should inspect a wider proof plan.",
			"fanout":          "bounded",
			"maxActionItems":  0,
			"maxCommandRefs":  hardMaxCommandRefs + 1,
			"maxContextRefs":  0,
			"maxOmittedItems": 0,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"omittedCount":    0,
		},
		Commands: commands,
	})
	if got := len(envelope["commands"].([]any)); got != hardMaxCommandRefs {
		t.Fatalf("command count=%d, want hard cap %d", got, hardMaxCommandRefs)
	}
	if containsCommandID(envelope["commands"].([]any), "proofkit.command.y") {
		t.Fatalf("commands include overflow item: %#v", envelope["commands"])
	}
	bounds := envelope["bounds"].(map[string]any)
	if bounds["fanout"] != "wide_or_full_gate_required" {
		t.Fatalf("bounds fanout=%v, want wide_or_full_gate_required", bounds["fanout"])
	}
	cost := envelope["costContract"].(map[string]any)
	if cost["omittedEdgeCount"] != 1 || cost["stopReason"] != "wide_or_full_gate_required" {
		t.Fatalf("unexpected cost contract: %#v", cost)
	}
	omitted := envelope["omitted"].([]any)
	if len(omitted) != 1 || omitted[0].(map[string]any)["sourceField"] != "commandId" {
		t.Fatalf("omitted=%#v, want command overflow record", omitted)
	}
}

func TestBuildPreservesSemanticOmittedCountWhenOmissionRecordsAreCapped(t *testing.T) {
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"reportId":   "proofkit.test.report",
			"reportKind": "proofkit.test",
			"state":      "passed",
		},
		Bounds: map[string]any{
			"escalation":      "Caller should inspect the source report for full omission detail.",
			"fanout":          "bounded",
			"maxActionItems":  0,
			"maxCommandRefs":  0,
			"maxContextRefs":  0,
			"maxOmittedItems": 1,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"omittedCount":    0,
		},
		Omitted: []map[string]any{
			{"omissionId": "proofkit.omitted.a", "omittedCount": 2},
			{"omissionId": "proofkit.omitted.b", "omittedCount": 3},
			{"omissionId": "proofkit.omitted.c", "omittedCount": 4},
		},
	})

	omitted := envelope["omitted"].([]any)
	if len(omitted) != 1 {
		t.Fatalf("omitted record count=%d, want capped single overflow record", len(omitted))
	}
	overflow := omitted[0].(map[string]any)
	if overflow["omissionId"] != "proofkit.agent-envelope.omitted.overflow" || overflow["omittedCount"] != 9 {
		t.Fatalf("overflow omitted record=%#v, want semantic omitted count 9", overflow)
	}
	bounds := envelope["bounds"].(map[string]any)
	if bounds["omittedCount"] != 9 {
		t.Fatalf("bounds omittedCount=%v, want 9", bounds["omittedCount"])
	}
	cost := envelope["costContract"].(map[string]any)
	if cost["omittedEdgeCount"] != 9 || cost["stopReason"] != "wide_or_full_gate_required" {
		t.Fatalf("unexpected cost contract: %#v", cost)
	}
}

func TestBuildProjectsSourceReportWhenEnvelopeIsTruncated(t *testing.T) {
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"artifactRef": "artifacts/proofkit/source.json",
			"debugDump":   []any{"large", "caller", "payload"},
			"reportId":    "proofkit.test.report",
			"reportKind":  "proofkit.test",
			"stableHash":  "sha256:test",
			"state":       "passed",
		},
		Bounds: map[string]any{
			"escalation":      "Caller should inspect a wider proof plan.",
			"fanout":          "bounded",
			"maxActionItems":  0,
			"maxCommandRefs":  0,
			"maxContextRefs":  0,
			"maxOmittedItems": 1,
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"omittedCount":    0,
		},
		Commands: []map[string]any{
			{"commandId": "proofkit.command.a"},
		},
	})
	sourceReport := envelope["sourceReport"].(map[string]any)
	if _, ok := sourceReport["debugDump"]; ok {
		t.Fatalf("projected source report leaked debugDump: %#v", sourceReport)
	}
	if sourceReport["artifactRef"] != "artifacts/proofkit/source.json" || sourceReport["state"] != "passed" {
		t.Fatalf("projected source report lost stable fields: %#v", sourceReport)
	}
}

func TestInvalidInputEnvelopePreservesRepairBoundary(t *testing.T) {
	envelope := InvalidInput("bad caller input")
	if envelope["envelopeId"] != "proofkit.agent-envelope.invalid-input" {
		t.Fatalf("unexpected envelope id: %v", envelope["envelopeId"])
	}
	if len(envelope["blockedPreconditions"].([]any)) != 1 {
		t.Fatalf("invalid input must create exactly one blocked precondition: %#v", envelope["blockedPreconditions"])
	}
	cost := envelope["costContract"].(map[string]any)
	if cost["stopReason"] != "blocked_precondition" {
		t.Fatalf("stopReason=%v want blocked_precondition", cost["stopReason"])
	}
}

func TestInvalidInputEnvelopeRedactsSecretLikeDiagnostics(t *testing.T) {
	secret := "ghp_FAKEFAKE1234567890"
	envelope := InvalidInput("missing pointer segment " + secret + "\n" + strings.Repeat("x", 600))
	text := ""
	for _, item := range envelope["blockedPreconditions"].([]any) {
		text += item.(map[string]any)["description"].(string)
	}
	for _, item := range envelope["actionPlan"].([]any) {
		text += item.(map[string]any)["rationale"].(string)
	}
	if strings.Contains(text, secret) {
		t.Fatalf("invalid input envelope leaked secret-shaped diagnostic: %s", text)
	}
	if !strings.Contains(text, "<redacted-secret-like-value>") {
		t.Fatalf("invalid input envelope text=%q, want redaction placeholder", text)
	}
	if !strings.Contains(text, "<redacted-control-rune>") {
		t.Fatalf("invalid input envelope text=%q, want control placeholder", text)
	}
	if !strings.Contains(text, "<truncated-diagnostic>") {
		t.Fatalf("invalid input envelope text=%q, want truncation marker", text)
	}
}

func TestBuildRedactsReportVisibleCallerTextAndSnapshotsInput(t *testing.T) {
	secret := "ghp_FAKEFAKE1234567890"
	sourceReport := map[string]any{
		"artifactRef": "artifacts/proofkit/source.json",
		"debugDump":   secret,
		"reportId":    "proofkit.test.report",
		"reportKind":  "proofkit.test",
		"stableHash":  "sha256:test",
		"state":       "passed",
	}
	action := map[string]any{
		"evidenceRefs": []any{"proofkit.evidence"},
		"rationale":    "do not print " + secret,
		"stepId":       "proofkit.agent.step",
	}
	blocked := map[string]any{
		"description":    "blocked by " + secret,
		"preconditionId": "proofkit.agent.blocked",
	}
	command := map[string]any{
		"commandId": "proofkit.command",
		"note":      "credential " + secret,
	}
	envelope := Build(Input{
		EnvelopeID:           secret,
		ActionPlan:           []map[string]any{action},
		BlockedPreconditions: []map[string]any{blocked},
		Commands:             []map[string]any{command},
		NonClaims:            []string{"caller non-claim " + secret},
		SourceReport:         sourceReport,
	})

	action["rationale"] = secret
	blocked["description"] = secret
	command["note"] = secret
	sourceReport["state"] = "failed"
	sourceReport["debugDump"] = secret

	assertEnvelopeDoesNotContain(t, envelope, secret)
	assertEnvelopeContains(t, envelope, "<redacted-secret-like-value>")
	projected := envelope["sourceReport"].(map[string]any)
	if _, ok := projected["debugDump"]; ok {
		t.Fatalf("sourceReport projection leaked debugDump: %#v", projected)
	}
	if projected["state"] != "passed" {
		t.Fatalf("sourceReport was not snapshotted before caller mutation: %#v", projected)
	}
}

func TestBuildPreservesStructuralArgvWithoutDiagnosticTruncation(t *testing.T) {
	longArg := "docs/" + strings.Repeat("x", 640) + "/coverage-input.json"
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"reportId":   "proofkit.test.report",
			"reportKind": "proofkit.test",
			"state":      "passed",
		},
		Commands: []map[string]any{
			{
				"argv":      []any{"agentic-proofkit", "requirement-coverage-view", "--input", longArg},
				"commandId": "proofkit.command.coverage",
			},
		},
	})

	commands := envelope["commands"].([]any)
	argv := commands[0].(map[string]any)["argv"].([]any)
	if got := argv[3]; got != longArg {
		t.Fatalf("argv[3]=%v, want untruncated structural arg", got)
	}
	serialized, err := stablejson.Marshal(envelope)
	if err != nil {
		t.Fatalf("stable serialize envelope: %v", err)
	}
	if strings.Contains(string(serialized), "<truncated-diagnostic>") {
		t.Fatalf("structural argv was diagnostic-truncated:\n%s", serialized)
	}
}

func TestBuildRedactsTypedContainersAndUnsupportedValues(t *testing.T) {
	secret := "ghp_TYPEDSECRET1234567890"
	typedMap := map[string]string{"note": secret}
	typedList := []map[string]string{{"detail": secret}}
	typedStrings := []string{"safe", secret}
	type definedMap map[string]any
	type definedSlice []any
	defined := definedMap{
		"nested": definedSlice{map[string]string{"token": secret}},
	}
	envelope := Build(Input{
		EnvelopeID: "proofkit.test.envelope",
		SourceReport: map[string]any{
			"reportId":   "proofkit.test.report",
			"reportKind": "proofkit.test",
			"state":      "passed",
		},
		ActionPlan: []map[string]any{
			{
				"stepId":       "proofkit.agent.step",
				"typedMap":     typedMap,
				"typedList":    typedList,
				"typedStrings": typedStrings,
				"defined":      defined,
				"jsonNumber":   json.Number("1"),
				"int64Number":  int64(2),
				"uint64Number": uint64(3),
				"floatValue":   1.5,
				"unsupported":  struct{ Token string }{Token: secret},
			},
		},
	})

	typedMap["note"] = secret + ".mutated"
	typedList[0]["detail"] = secret + ".mutated"
	typedStrings[1] = secret + ".mutated"
	defined["nested"] = definedSlice{secret + ".mutated"}

	assertEnvelopeDoesNotContain(t, envelope, secret)
	assertEnvelopeContains(t, envelope, "<redacted-secret-like-value>")
	assertEnvelopeContains(t, envelope, "<unsupported-report-visible-value>")
	serialized, err := stablejson.Marshal(envelope)
	if err != nil {
		t.Fatalf("stable serialize envelope: %v", err)
	}
	if !strings.Contains(string(serialized), `"jsonNumber": 1`) {
		t.Fatalf("json.Number was not preserved as a JSON number:\n%s", serialized)
	}
	if !strings.Contains(string(serialized), `"int64Number": 2`) || !strings.Contains(string(serialized), `"uint64Number": 3`) {
		t.Fatalf("integer values were not converted to stable JSON numbers:\n%s", serialized)
	}
	if strings.Contains(string(serialized), `"floatValue": 1.5`) {
		t.Fatalf("float value should not be emitted as stable JSON number:\n%s", serialized)
	}
}

func assertFirstID(t *testing.T, raw any, key string, want string) {
	t.Helper()
	values := raw.([]any)
	if len(values) == 0 {
		t.Fatalf("%s list empty", key)
	}
	got := values[0].(map[string]any)[key]
	if got != want {
		t.Fatalf("first %s=%v want %s", key, got, want)
	}
}

func containsCommandID(values []any, commandID string) bool {
	for _, value := range values {
		record := value.(map[string]any)
		if record["commandId"] == commandID {
			return true
		}
	}
	return false
}

func assertEnvelopeDoesNotContain(t *testing.T, envelope map[string]any, needle string) {
	t.Helper()
	serialized, err := stablejson.Marshal(envelope)
	if err != nil {
		t.Fatalf("stable serialize envelope: %v", err)
	}
	if strings.Contains(string(serialized), needle) {
		t.Fatalf("envelope leaked %q:\n%s", needle, serialized)
	}
}

func assertEnvelopeContains(t *testing.T, envelope map[string]any, needle string) {
	t.Helper()
	serialized, err := stablejson.Marshal(envelope)
	if err != nil {
		t.Fatalf("stable serialize envelope: %v", err)
	}
	if !strings.Contains(string(serialized), needle) {
		t.Fatalf("envelope missing %q:\n%s", needle, serialized)
	}
}
