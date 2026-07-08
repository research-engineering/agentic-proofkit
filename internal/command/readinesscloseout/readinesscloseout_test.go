package readinesscloseout

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func TestBuildAdmitsClosedFrontierAndRejectsMissingClosedPhrase(t *testing.T) {
	markdown := strings.Join([]string{
		"### Production Readiness Roadmap",
		"| Status | ID | Owner scope | Completion condition |",
		"|---|---|---|---|",
		"| DONE | PROD-01 | Alpha input | Alpha phrase |",
		"| DONE | PROD-09 | Closeout | Frontier closed Closure gates: |",
	}, "\n")
	record, status, err := Build(minimalCloseoutInput(markdown))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if status != 0 || record.State != "passed" {
		t.Fatalf("Build() status=%d state=%s, want passed", status, record.State)
	}

	record, status, err = Build(minimalCloseoutInput(strings.ReplaceAll(markdown, "Closure gates:", "No closure text")))
	if err != nil {
		t.Fatalf("Build() missing phrase error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted missing closed phrase: status=%d record=%#v", status, record)
	}
	for _, rule := range record.RuleResults {
		if rule.RuleID == "PROD-09.frontier.non_claims" && strings.Contains(rule.Message, "Closure gates:") {
			return
		}
	}
	t.Fatalf("missing frontier phrase failure: %#v", record.RuleResults)
}

func TestBuildReportsDuplicateBacklogRowFailure(t *testing.T) {
	record, status, err := Build(minimalCloseoutInput(strings.Join([]string{
		"### Production Readiness Roadmap",
		"| Status | ID | Owner scope | Completion condition |",
		"|---|---|---|---|",
		"| DONE | PROD-01 | Alpha input | Alpha phrase |",
		"| DONE | PROD-09 | Closeout | Frontier closed Closure gates: |",
		"| DONE | PROD-01 | Duplicate input | Duplicate phrase |",
	}, "\n")))
	if err != nil {
		t.Fatalf("build closeout report: %v", err)
	}
	if status != 1 {
		t.Fatalf("expected duplicate row failure status, got %d", status)
	}
	if record.State != "failed" {
		t.Fatalf("expected failed state, got %s", record.State)
	}
	for _, rule := range record.RuleResults {
		if rule.RuleID == "PROD-09.backlog_rows.unique" {
			if rule.Status != "failed" {
				t.Fatalf("duplicate row rule status=%s want failed", rule.Status)
			}
			if !strings.Contains(rule.Message, "PROD-01 appears more than once in backlog tables") {
				t.Fatalf("duplicate row rule message lost failure detail: %q", rule.Message)
			}
			return
		}
	}
	t.Fatalf("missing duplicate row rule result: %#v", record.RuleResults)
}

func TestBuildRejectsShellControlExactCommand(t *testing.T) {
	input := minimalCloseoutInput("### Production Readiness Roadmap\n")
	input["exactCommand"] = "proofkit readiness closeout && curl example.test"

	record, status, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() status=%d state=%s, want failed", status, record.State)
	}
	for _, rule := range record.RuleResults {
		if strings.Contains(rule.Message, "display-only command text") {
			return
		}
	}
	t.Fatalf("missing display-only command failure: %#v", record.RuleResults)
}

func TestBuildRejectsSecretLikeReportTextThroughCentralAdmission(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := minimalCloseoutInput(closedFrontierMarkdown())
	input["nonClaims"] = []any{secret}

	record, status, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() status=%d state=%s, want failed", status, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("readiness report leaked secret-shaped caller text: %s", string(encoded))
	}
	assertRuleMessageContains(t, record, "readiness_closeout.input", "secret-like values")
}

func TestBuildRejectsCallerControlledReportKind(t *testing.T) {
	input := minimalCloseoutInput(closedFrontierMarkdown())
	input["reportKind"] = "caller.controlled.kind"

	record, status, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() status=%d state=%s, want failed", status, record.State)
	}
	if record.ReportKind != "proofkit.readiness-closeout" {
		t.Fatalf("ReportKind=%q, want command-owned identity", record.ReportKind)
	}
	assertRuleMessageContains(t, record, "readiness_closeout.input", "unsupported field")
}

func TestBuildRejectsPassedClassificationForBlockedOwnerRow(t *testing.T) {
	markdown := strings.Join([]string{
		"### Production Readiness Roadmap",
		"| Status | ID | Owner scope | Completion condition |",
		"|---|---|---|---|",
		"| BLOCKED | PROD-01 | Alpha input | Alpha phrase |",
		"| DONE | PROD-09 | Closeout | Frontier closed Closure gates: |",
	}, "\n")
	input := minimalCloseoutInput(markdown)
	input["inputDefinitions"] = []any{
		map[string]any{
			"rowId":          "PROD-01",
			"expectedStatus": "BLOCKED",
			"classification": "passed",
			"evidenceClass":  "local_contract_gate",
			"reason":         "test input",
			"requiredText":   []any{"Alpha phrase"},
		},
	}

	record, status, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() status=%d state=%s, want failed", status, record.State)
	}
	assertRuleMessageContains(t, record, "PROD-09.PROD-01.classification", "passed classification requires DONE owner status")
}

func TestBuildAddsMandatoryBoundaryNonClaims(t *testing.T) {
	record, status, err := Build(minimalCloseoutInput(closedFrontierMarkdown()))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if status != 0 || record.State != "passed" {
		t.Fatalf("Build() status=%d state=%s, want passed", status, record.State)
	}
	if !recordNonClaimContains(record, "Readiness closeout reports do not execute gates, authenticate receipts, publish artifacts, approve merge, or prove deployment readiness.") {
		t.Fatalf("NonClaims missing command-owned boundary denial: %#v", record.NonClaims)
	}
}

func TestBuildRejectsBroadNegationAndFrontierOverclaim(t *testing.T) {
	markdown := closedFrontierMarkdown(
		"Future authoring rows must not require separate owner proof before merge authority is established.",
	)
	input := minimalCloseoutInput(markdown)
	input["phraseRules"] = []any{frontierAuthorityPhraseRule()}
	input["negatedNonClaimPhrases"] = []any{"must not"}

	record, status, err := Build(input)
	if err != nil {
		t.Fatalf("Build() broad negation error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted broad negation: status=%d record=%#v", status, record)
	}
	assertRuleMessageContains(t, record, "readiness_closeout.input", "scoped non-claim predicate")

	input = minimalCloseoutInput(markdown)
	input["phraseRules"] = []any{frontierAuthorityPhraseRule()}
	input["negatedNonClaimPhrases"] = []any{"must not claim"}

	record, status, err = Build(input)
	if err != nil {
		t.Fatalf("Build() scoped negation error=%v", err)
	}
	if status == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted frontier overclaim: status=%d record=%#v", status, record)
	}
	assertRuleMessageContains(t, record, "PROD-09.frontier.non_claims", "live authority claim")

	safeInput := minimalCloseoutInput(closedFrontierMarkdown(
		"Future authoring rows must not claim merge authority is established.",
	))
	safeInput["phraseRules"] = []any{frontierAuthorityPhraseRule()}
	safeInput["negatedNonClaimPhrases"] = []any{"must not claim"}

	record, status, err = Build(safeInput)
	if err != nil {
		t.Fatalf("Build() safe scoped non-claim error=%v", err)
	}
	if status != 0 || record.State != "passed" {
		t.Fatalf("Build() rejected safe scoped non-claim: status=%d record=%#v", status, record)
	}
}

func TestBuildRejectsScopeFreeNegatedNonClaimPhrases(t *testing.T) {
	for _, phrase := range []string{"must not", "do not", "does not", "not", "no", "non claim", "later row", "is blocked", "blocked on later rows", "blocked until later row", "remains blocked on later rows"} {
		t.Run(phrase, func(t *testing.T) {
			input := minimalCloseoutInput(closedFrontierMarkdown())
			input["negatedNonClaimPhrases"] = []any{phrase}

			record, status, err := Build(input)
			if err != nil {
				t.Fatalf("Build() broad phrase error=%v", err)
			}
			if status == 0 || record.State != "failed" {
				t.Fatalf("Build() accepted broad phrase %q: status=%d record=%#v", phrase, status, record)
			}
			assertRuleMessageContains(t, record, "readiness_closeout.input", "scoped non-claim predicate")
		})
	}
}

func TestBuildAdmitsConcreteBlockedScopeNonClaimPhrase(t *testing.T) {
	input := minimalCloseoutInput(closedFrontierMarkdown(
		"Future authoring rows remain blocked on public-source tag release.",
	))
	input["phraseRules"] = []any{frontierAuthorityPhraseRule()}
	input["negatedNonClaimPhrases"] = []any{"remain blocked on public source tag release"}

	record, status, err := Build(input)
	if err != nil {
		t.Fatalf("Build() concrete blocked scope error=%v", err)
	}
	if status != 0 || record.State != "passed" {
		t.Fatalf("Build() rejected concrete blocked scope: status=%d record=%#v", status, record)
	}
}

func minimalCloseoutInput(markdown string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"markdownText":  markdown,
		"reportId":      "PROD-09.closeout",
		"exactCommand":  "proofkit readiness closeout",
		"runIdentity":   "test_run",
		"environmentPreconditions": []any{
			"local",
		},
		"readinessSections": []any{
			"Production Readiness Roadmap",
		},
		"readinessRowPrefixes": []any{
			"PROD-",
		},
		"inputDefinitions": []any{
			map[string]any{
				"rowId":          "PROD-01",
				"expectedStatus": "DONE",
				"classification": "passed",
				"evidenceClass":  "local_contract_gate",
				"reason":         "test input",
				"requiredText": []any{
					"Alpha phrase",
				},
			},
		},
		"frontier": map[string]any{
			"rowId":        "PROD-09",
			"openStatus":   "NEXT",
			"closedStatus": "DONE",
			"openRequiredText": []any{
				"Frontier open",
			},
			"closedRequiredText": []any{
				"Frontier closed",
			},
			"closedRowRequiredText": []any{
				"Closure gates:",
			},
		},
		"phraseRules":            []any{},
		"negatedNonClaimPhrases": []any{},
		"nonClaims": []any{
			"test non-claim",
		},
	}
}

func closedFrontierMarkdown(extraLines ...string) string {
	lines := []string{
		"### Production Readiness Roadmap",
		"| Status | ID | Owner scope | Completion condition |",
		"|---|---|---|---|",
		"| DONE | PROD-01 | Alpha input | Alpha phrase |",
		"| DONE | PROD-09 | Closeout | Frontier closed Closure gates: |",
	}
	lines = append(lines, extraLines...)
	return strings.Join(lines, "\n")
}

func frontierAuthorityPhraseRule() map[string]any {
	return map[string]any{
		"ruleId":             "live-authority-claim",
		"subjectPhrases":     []any{"future authoring rows"},
		"evidencePhrases":    []any{"merge authority"},
		"predicatePhrases":   []any{"established"},
		"directClaimPhrases": []any{},
		"failureMessage":     "live authority claim",
	}
}

func assertRuleMessageContains(t *testing.T, record report.Record, ruleID string, messagePart string) {
	t.Helper()
	for _, rule := range record.RuleResults {
		if rule.RuleID == ruleID && strings.Contains(rule.Message, messagePart) {
			return
		}
	}
	t.Fatalf("missing %s rule message containing %q: %#v", ruleID, messagePart, record.RuleResults)
}

func recordNonClaimContains(record report.Record, want string) bool {
	for _, value := range record.NonClaims {
		if text, ok := value.(string); ok && text == want {
			return true
		}
	}
	return false
}
