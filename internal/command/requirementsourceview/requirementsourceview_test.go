package requirementsourceview

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"regexp"
	"strings"
	"testing"
)

func TestHTMLModesShareCompleteRequirementSearch(t *testing.T) {
	input := validRequirementSource()
	requirement := input["requirements"].([]any)[0].(map[string]any)
	requirement["nonClaimRefs"] = []any{"NC-RENDERING-001"}
	requirement["lifecycle"].(map[string]any)["evidenceRefs"] = []any{"review.rendering"}
	output, code, err := BuildHTML(input)
	if err != nil || code != 0 {
		t.Fatalf("BuildHTML() code=%d error=%v", code, err)
	}
	search := regexp.MustCompile(`data-search="([^"]*)"`).FindAllStringSubmatch(output, -1)
	if len(search) != 2 || search[0][1] != search[1][1] {
		t.Fatal("card and table must search the same complete requirement record")
	}
	for _, value := range []string{
		"REQ-PROOFKIT-VIEW-001", "proofkit.test",
		"Renderer must preserve caller-controlled text safely.",
		"blocking", "medium", "active", "NC-RENDERING-001", "review.rendering",
		"docs/contracts/requirement-proof-binding-sources.v1.json",
		"This test requirement does not execute native witnesses.",
	} {
		if !strings.Contains(search[0][1], strings.ToLower(value)) {
			t.Fatalf("shared search omitted %q", value)
		}
	}
}

func TestHTMLModesSearchReplacementReferences(t *testing.T) {
	input := validRequirementSource()
	requirement := input["requirements"].([]any)[0].(map[string]any)
	replacement := validRequirementSource()["requirements"].([]any)[0].(map[string]any)
	replacement["requirementId"] = "REQ-PROOFKIT-VIEW-002"
	requirement["claimLevel"] = "advisory"
	requirement["lifecycle"] = map[string]any{
		"state": "superseded", "evidenceRefs": []any{"review.replacement"},
		"replacementRequirementIds": []any{"REQ-PROOFKIT-VIEW-002"},
	}
	input["requirements"] = append(input["requirements"].([]any), replacement)
	output, code, err := BuildHTML(input)
	if err != nil || code != 0 {
		t.Fatalf("BuildHTML() code=%d error=%v", code, err)
	}
	matched := 0
	for _, search := range regexp.MustCompile(`data-search="([^"]*)"`).FindAllStringSubmatch(output, -1) {
		if strings.Contains(search[1], "req-proofkit-view-001") {
			matched++
			if !strings.Contains(search[1], "req-proofkit-view-002") {
				t.Fatal("superseded requirement search omitted its replacement reference")
			}
		}
	}
	if matched != 2 {
		t.Fatal("both projections of the superseded requirement must be checked")
	}
}

func TestBuildMarkdownEscapesCallerControlledText(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.115603095301227499403457054570913397276777831949518460396011319173029743458113")
	input := validRequirementSource()
	input["specPackagePath"] = "docs/specs/proofkit-`<img src=x onerror=alert(1)>`"
	input["overviewPath"] = "docs/specs/proofkit-`<img src=x onerror=alert(1)>`/overview.md"
	input["requirementsPath"] = "docs/specs/proofkit-`<img src=x onerror=alert(1)>`/requirements.v1.json"
	requirement := input["requirements"].([]any)[0].(map[string]any)
	requirement["invariant"] = "Renderer must not emit <img src=x onerror=alert(1)> as raw Markdown HTML.\n# forged heading\n![x](https://example.test/x)\n| a | b |"
	requirement["nonClaims"] = []any{"Non-claim contains <script>alert(1)</script> and must be escaped."}
	requirement["proofBindingRefs"] = []any{"docs/contracts/`<img src=x onerror=alert(1)>`.json"}

	output, exitCode, err := BuildMarkdown(input)
	if err != nil {
		t.Fatalf("BuildMarkdown() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildMarkdown() exitCode=%d, want 0", exitCode)
	}
	if strings.Contains(output, "<img") || strings.Contains(output, "<script>") || strings.Contains(output, "\n# forged heading") || strings.Contains(output, "![x](") || strings.Contains(output, "| a | b |") {
		t.Fatalf("Markdown output contains raw HTML or Markdown structure sink: %s", output)
	}
	if !strings.Contains(output, "&lt;img") || !strings.Contains(output, "&lt;script&gt;") {
		t.Fatalf("Markdown output did not escape HTML markers: %s", output)
	}
	for _, want := range []string{"\\# forged heading", "\\!\\[x\\]", "\\| a \\| b \\|"} {
		if !strings.Contains(output, want) {
			t.Fatalf("Markdown output missing escaped structural marker %q: %s", want, output)
		}
	}
	if strings.Contains(output, "`docs/contracts/\\`") {
		t.Fatalf("Markdown output uses unsafe backslash-escaped code span: %s", output)
	}
	if !strings.Contains(output, "``docs/contracts/`&lt;img src=x onerror=alert(1)&gt;`.json``") {
		t.Fatalf("Markdown output did not use a longer code-span delimiter: %s", output)
	}
	for _, want := range []string{
		"``docs/specs/proofkit-`&lt;img src=x onerror=alert(1)&gt;```",
		"``docs/specs/proofkit-`&lt;img src=x onerror=alert(1)&gt;`/overview.md``",
		"``docs/specs/proofkit-`&lt;img src=x onerror=alert(1)&gt;`/requirements.v1.json``",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Markdown output did not safely render caller-controlled path %q: %s", want, output)
		}
	}
}

func validRequirementSource() map[string]any {
	return map[string]any{
		"schemaVersion":    json.Number("1"),
		"sourceId":         "proofkit.test.requirements",
		"specPackagePath":  "docs/specs/proofkit-test",
		"overviewPath":     "docs/specs/proofkit-test/overview.md",
		"requirementsPath": "docs/specs/proofkit-test/requirements.v1.json",
		"nonClaims":        []any{"Requirement source view test input does not claim merge readiness."},
		"requirements": []any{
			map[string]any{
				"claimLevel": "blocking",
				"deferral":   nil,
				"invariant":  "Renderer must preserve caller-controlled text safely.",
				"lifecycle": map[string]any{
					"evidenceRefs":              []any{},
					"replacementRequirementIds": []any{},
					"state":                     "active",
				},
				"nonClaimRefs": []any{},
				"nonClaims":    []any{"This test requirement does not execute native witnesses."},
				"ownerId":      "proofkit.test",
				"proofBindingRefs": []any{
					"docs/contracts/requirement-proof-binding-sources.v1.json",
				},
				"requirementId": "REQ-PROOFKIT-VIEW-001",
				"riskClass":     "medium",
				"updatePolicy": map[string]any{
					"requiresImpactDeclaration":  true,
					"requiresProofBindingReview": true,
					"reviewOwnerId":              "proofkit.test",
				},
			},
		},
	}
}
