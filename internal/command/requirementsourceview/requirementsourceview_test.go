package requirementsourceview

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildMarkdownEscapesCallerControlledText(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.079155125739683862685982535478403487660808558239998414186036088598924884165357")
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
