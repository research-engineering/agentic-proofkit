package readinesscloseout

import (
	"strings"
	"testing"
)

func TestBuildDoesNotClassifyExamplesAsPolicyRows(t *testing.T) {
	const heading = "### Production Readiness Roadmap"
	const example = "| Status | ID | Scope | Completion |\n|---|---|---|---|\n| DONE | PROD-01 | Alpha input | Alpha phrase |\n| DONE | PROD-09 | Closeout | Frontier closed Closure gates: |"
	for _, markdown := range []string{
		heading + "\n\nDONE | PROD-01 | Alpha input | Alpha phrase\n\nDONE | PROD-09 | Closeout | Frontier closed Closure gates:",
		heading + "\n\n```markdown\n" + example + "\n```",
		heading + "\n\n<!--\n" + example + "\n-->",
		heading + "\n\n> " + strings.ReplaceAll(example, "\n", "\n> "),
	} {
		record, code, err := Build(minimalCloseoutInput(markdown))
		if err != nil || code != 1 || record.State != "failed" {
			t.Fatalf("example supplied policy rows: exit=%d state=%s err=%v", code, record.State, err)
		}
		assertRuleMessageContains(t, record, "PROD-09.frontier.non_claims", "PROD-09 closeout row is missing from backlog")
	}
	valid := closedFrontierMarkdown("", "NEXT | PROD-77 | Example only | Not an open policy row")
	record, code, err := Build(minimalCloseoutInput(valid))
	if err != nil || code != 0 || record.State != "passed" {
		t.Fatalf("paragraph outside a table reopened policy: exit=%d state=%s err=%v", code, record.State, err)
	}
}

func TestBuildPreservesOpenRowsWithOptionalEdgesAndMissingDescription(t *testing.T) {
	for _, edge := range []struct{ leading, trailing string }{{}, {"| ", ""}, {"", " |"}, {"| ", " |"}} {
		lines := []string{"### Production Readiness Roadmap", "Status | ID | Scope | Completion", "--- | :---: | --- | ---:",
			"DONE | PROD-01 | Alpha input | Alpha phrase", "DONE | PROD-09 | Closeout | Frontier closed Closure gates:"}
		for i := 1; i < len(lines); i++ {
			lines[i] = edge.leading + lines[i] + edge.trailing
		}
		valid := strings.Join(lines, "\n")
		record, code, err := Build(minimalCloseoutInput(valid))
		if err != nil || code != 0 || record.State != "passed" {
			t.Fatalf("real policy table refused: exit=%d state=%s err=%v", code, record.State, err)
		}
		record, code, err = Build(minimalCloseoutInput(valid + "\n" + edge.leading + "NEXT | PROD-77" + edge.trailing))
		if err != nil || code != 1 || record.State != "failed" {
			t.Fatalf("sparse open row disappeared: exit=%d state=%s err=%v", code, record.State, err)
		}
	}
}

func TestBuildRecognizesOnlyPolicyHeaders(t *testing.T) {
	for _, tc := range []struct {
		header string
		state  string
		exit   int
	}{
		{"Status | ID", "failed", 1},
		{"State | ID", "passed", 0},
		{"Status | Reference", "passed", 0},
	} {
		t.Run(tc.header, func(t *testing.T) {
			markdown := closedFrontierMarkdown("", "| "+tc.header+" | Scope | Completion |", "|---|---|---|---|", "| NEXT | PROD-77 | Pending review | Still open |")
			record, code, err := Build(minimalCloseoutInput(markdown))
			if err != nil || code != tc.exit || record.State != tc.state {
				t.Fatalf("header admission: exit=%d state=%s err=%v", code, record.State, err)
			}
		})
	}
}

func TestBuildRejectsTopLevelAndNestedTableAmplificationBeforeParsing(t *testing.T) {
	for _, prefix := range []string{"", "> "} {
		wide := prefix + strings.Repeat("head|", 512) + "head\n" + prefix + strings.Repeat("---|", 512) + "---\n" + strings.Repeat(prefix+"one\n", 512)
		record, code, err := Build(minimalCloseoutInput(wide))
		if err == nil || !strings.Contains(err.Error(), "cell table parsing limit") || code != 1 || record.State != "" {
			t.Fatalf("wrong table budget outcome: exit=%d state=%s err=%v", code, record.State, err)
		}
	}
}

func TestBuildBoundsMarkdownBytesAndNestingCarrier(t *testing.T) {
	for _, tc := range []struct{ markdown, diagnostic string }{
		{strings.Repeat("a", maxPolicyMarkdownBytes+1), "byte table parsing limit"},
		{strings.Repeat("> ", maxPolicyMarkdownLine/2+1) + "example", "contains a line above"},
	} {
		record, code, err := Build(minimalCloseoutInput(tc.markdown))
		if err == nil || !strings.Contains(err.Error(), tc.diagnostic) || code != 1 || record.State != "" {
			t.Fatalf("wrong Markdown budget outcome: exit=%d state=%s err=%v", code, record.State, err)
		}
	}
}
