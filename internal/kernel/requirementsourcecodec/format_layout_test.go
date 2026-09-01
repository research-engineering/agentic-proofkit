package requirementsourcecodec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestHybridLayoutKeepsStableSiblingEntityLinesUnchanged(t *testing.T) {
	beforeDraft := testDraft()
	before := mustFormatDraft(t, beforeDraft)
	afterDraft := testDraft()
	afterDraft.Groups[0].Members[1].StatementCompletion = "reject invalid requests."
	after := mustFormatDraft(t, afterDraft)

	stableBefore := lineContaining(t, before, `"requirementId":"REQ-CODEC-001"`)
	stableAfter := lineContaining(t, after, `"requirementId":"REQ-CODEC-001"`)
	if stableBefore != stableAfter {
		t.Fatalf("stable sibling line changed:\n-%s\n+%s", stableBefore, stableAfter)
	}
	changedBefore := lineContaining(t, before, `"requirementId":"REQ-CODEC-002"`)
	changedAfter := lineContaining(t, after, `"requirementId":"REQ-CODEC-002"`)
	if changedBefore == changedAfter {
		t.Fatal("changed entity line did not change")
	}
	if strings.Contains(changedAfter, "REQ-CODEC-001") {
		t.Fatal("changed entity line contains a stable sibling")
	}
}

func TestHybridLayoutUsesCommaFirstEntityArrays(t *testing.T) {
	payload := mustPayload(t)
	if !bytes.Contains(payload, []byte("\n    {\"nonClaimId\":\"NCL-CODEC-001\"")) {
		t.Fatal("first entity is not independently line-addressable")
	}
	if !bytes.Contains(payload, []byte("\n  , {\"nonClaimId\":\"NCL-CODEC-002\"")) {
		t.Fatal("subsequent entity does not use comma-first layout")
	}
}

func TestCanonicalStringsEscapeUnsafeScalarsWithoutHTMLEscaping(t *testing.T) {
	draft := testDraft()
	draft.Groups[0].Members[0].StatementCompletion = "accept <safe/>& requests.\u0085\u200b\u2028\u2029\U000e0001"
	payload := mustFormatDraft(t, draft)
	if !bytes.Contains(payload, []byte(`accept <safe/>& requests.\u0085\u200b\u2028\u2029\udb40\udc01`)) {
		t.Fatalf("canonical string policy mismatch:\n%s", payload)
	}
	if bytes.Contains(payload, []byte(`\u003c`)) || bytes.Contains(payload, []byte(`\/`)) {
		t.Fatal("formatter applied HTML or slash escaping")
	}
	parsed, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	expected, err := requirementsourcemodel.Normalize(draft)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if !projectionsEqual(parsed.Model, expected) {
		t.Fatal("unsafe-scalar escaping changed model semantics")
	}
}

func TestCanonicalMapKeysAreSorted(t *testing.T) {
	draft := testDraft()
	draft.Scenarios[0].Parameters = []string{"alpha", "surface", "zeta"}
	draft.Scenarios[0].Preconditions = []string{"The ${alpha}, ${surface}, and ${zeta} inputs are available."}
	draft.Scenarios[0].Examples = []requirementsourcemodel.Example{
		{ExampleID: "EX-CODEC-REQUEST-001", Values: map[string]requirementsourcemodel.ScenarioValue{"zeta": "z", "surface": "primary", "alpha": "a"}},
		{ExampleID: "EX-CODEC-REQUEST-002", Values: map[string]requirementsourcemodel.ScenarioValue{"zeta": "zz", "surface": "secondary", "alpha": "aa"}},
	}
	payload := mustFormatDraft(t, draft)
	if !bytes.Contains(payload, []byte(`"values":{"alpha":"a","surface":"primary","zeta":"z"}`)) {
		t.Fatalf("dynamic map keys are not canonical:\n%s", payload)
	}
}

func TestOrderedActionsRetainOrder(t *testing.T) {
	draft := testDraft()
	draft.Scenarios[0].ActionSequence = []string{"Third action.", "First action.", "Second action."}
	payload := mustFormatDraft(t, draft)
	result, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	actions := result.Model.Atomic().Scenarios[0].ActionSequence
	want := draft.Scenarios[0].ActionSequence
	if strings.Join(actions, "|") != strings.Join(want, "|") {
		t.Fatalf("actions = %#v, want %#v", actions, want)
	}
}

func mustFormatDraft(t *testing.T, draft requirementsourcemodel.Draft) []byte {
	t.Helper()
	model, err := requirementsourcemodel.Normalize(draft)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	payload, err := Format(model)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	return payload
}

func lineContaining(t *testing.T, payload []byte, needle string) string {
	t.Helper()
	for _, line := range strings.Split(string(payload), "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("line containing %q not found", needle)
	return ""
}
