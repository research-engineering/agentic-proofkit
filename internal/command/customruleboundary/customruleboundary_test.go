package customruleboundary

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildAdmitsBoundedCustomRuleAndRejectsUnsafeEffects(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.106806151242803002240171487302316779109328290727609414333938322871488003612890")
	record, exitCode, err := Build(validCustomRuleBoundaryInput())
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		message string
	}{
		{
			name: "proofkit namespace",
			mutate: func(input map[string]any) {
				rule := firstCustomRule(input)
				rule["namespace"] = "proofkit.custom"
				rule["ruleId"] = "proofkit.custom.local-check"
			},
			message: "must not use proofkit-owned namespace",
		},
		{
			name: "generic decision satisfy",
			mutate: func(input map[string]any) {
				firstCustomRule(input)["genericDecisionEffect"] = "satisfy"
			},
			message: "must not downgrade or satisfy generic decision state",
		},
		{
			name: "network access",
			mutate: func(input map[string]any) {
				firstCustomRule(input)["networkPolicy"] = "external"
			},
			message: "must not access network",
		},
		{
			name: "credential access",
			mutate: func(input map[string]any) {
				firstCustomRule(input)["credentialPolicy"] = "live"
			},
			message: "must not access credentials",
		},
		{
			name: "missing secret redaction",
			mutate: func(input map[string]any) {
				firstCustomRule(input)["deterministicOutput"].(map[string]any)["secretRedaction"] = false
			},
			message: "must declare secret redaction",
		},
		{
			name: "catch all glob",
			mutate: func(input map[string]any) {
				firstCustomRule(input)["affectedPathGlobs"] = []any{"**/*"}
			},
			message: "must not use repository-wide catch-all affected globs",
		},
		{
			name: "command remediation without command",
			mutate: func(input map[string]any) {
				firstCustomRule(input)["remediation"].(map[string]any)["commandRefs"] = []any{}
			},
			message: "command_ref remediation must declare command refs",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validCustomRuleBoundaryInput()
			item.mutate(input)

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			if !customRuleFailureContains(record.Diagnostics, item.message) {
				t.Fatalf("diagnostics=%#v, want %q", record.Diagnostics, item.message)
			}
		})
	}
}

func validCustomRuleBoundaryInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"boundaryId":    "consumer.custom-rule.boundary",
		"profileRef":    "proofkit/repo-profile.v1.json",
		"nonClaims":     []any{"Consumer custom-rule boundary test input does not execute custom rules."},
		"rules": []any{
			map[string]any{
				"affectedPathGlobs":     []any{"docs/specs/**/*.json"},
				"boundaryRole":          "local_diagnostics_only",
				"credentialPolicy":      "none",
				"genericDecisionEffect": "no_downgrade",
				"genericFindingEffect":  "append_only",
				"inputArtifactKinds":    []any{"consumer.requirement-source"},
				"inputArtifactRefs":     []any{"docs/specs/review/requirements.v1.json"},
				"namespace":             "consumer.review",
				"networkPolicy":         "none",
				"nonClaims":             []any{"Consumer custom rule test input does not prove merge readiness."},
				"outputSchemaRef":       "proofkit/custom-rule-output.schema.json",
				"owner":                 "consumer-review-owners",
				"ruleId":                "consumer.review.comment-format",
				"severity":              "error",
				"deterministicOutput": map[string]any{
					"secretRedaction":  true,
					"stableFindingIds": true,
					"stableOrdering":   true,
				},
				"remediation": map[string]any{
					"commandRefs": []any{"consumer.review.verify"},
					"kind":        "command_ref",
					"summary":     "Run the consumer-owned verification command.",
				},
				"removal": map[string]any{
					"condition": "Remove after the consumer repository replaces this local rule with a proofkit-native invariant.",
					"owner":     "consumer-review-owners",
					"reviewRef": "docs/reviews/custom-rule-boundary.md",
				},
				"useLimit": map[string]any{
					"maxAffectedPathGlobs": json.Number("2"),
					"rationale":            "Keep the custom rule bounded to the review specification module.",
					"scope":                "module_scoped",
				},
			},
		},
	}
}

func firstCustomRule(input map[string]any) map[string]any {
	return input["rules"].([]any)[0].(map[string]any)
}

func customRuleFailureContains(diagnostics []report.Diagnostic, needle string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Key != "failures" {
			continue
		}
		for _, value := range diagnostic.Value.([]any) {
			if strings.Contains(value.(string), needle) {
				return true
			}
		}
	}
	return false
}
