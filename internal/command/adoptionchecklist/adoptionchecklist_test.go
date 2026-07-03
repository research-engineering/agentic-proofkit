package adoptionchecklist

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func TestBuildClassifiesRequiredChecklistItemsAndPreservesOptionalNonFailures(t *testing.T) {
	record, exitCode, err := Build(validChecklistInput())
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	if record.Summary["requiredItemCount"] != 1 || record.Summary["satisfiedRequiredCount"] != 1 {
		t.Fatalf("summary=%#v, want one satisfied required item", record.Summary)
	}

	cases := []struct {
		name       string
		mutate     func(map[string]any)
		wantError  string
		wantResult string
	}{
		{
			name: "required missing",
			mutate: func(input map[string]any) {
				firstChecklistItem(input)["status"] = "missing"
				firstChecklistItem(input)["evidenceRefs"] = []any{}
			},
			wantResult: "required item proofkit.adoption.profile is missing",
		},
		{
			name: "required blocked",
			mutate: func(input map[string]any) {
				item := firstChecklistItem(input)
				item["status"] = "blocked"
				item["evidenceRefs"] = []any{}
				item["blocker"] = "caller must approve the repository profile"
			},
			wantResult: "required item proofkit.adoption.profile is blocked",
		},
		{
			name: "required not applicable",
			mutate: func(input map[string]any) {
				firstChecklistItem(input)["status"] = "not_applicable"
				firstChecklistItem(input)["evidenceRefs"] = []any{}
			},
			wantResult: "required item proofkit.adoption.profile is not applicable",
		},
		{
			name: "undeclared required item",
			mutate: func(input map[string]any) {
				input["requiredItemIds"] = []any{"proofkit.adoption.missing-item"}
			},
			wantResult: "required item proofkit.adoption.missing-item must reference a declared checklist item",
		},
		{
			name: "duplicate item ids",
			mutate: func(input map[string]any) {
				input["items"] = append(input["items"].([]any), firstChecklistItem(input))
			},
			wantError: "item ids must be sorted and unique",
		},
		{
			name: "satisfied item without evidence",
			mutate: func(input map[string]any) {
				firstChecklistItem(input)["evidenceRefs"] = []any{}
			},
			wantError: "satisfied adoption checklist items must declare at least one evidence ref",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validChecklistInput()
			item.mutate(input)

			record, exitCode, err := Build(input)
			if item.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), item.wantError) {
					t.Fatalf("Build() error=%v, want %q", err, item.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			if !checklistRuleMessageContains(record.RuleResults, item.wantResult) {
				t.Fatalf("ruleResults=%#v, want %q", record.RuleResults, item.wantResult)
			}
		})
	}
}

func validChecklistInput() map[string]any {
	return map[string]any{
		"schemaVersion":   json.Number("1"),
		"checklistId":     "proofkit.test.adoption-checklist",
		"scenario":        "new_repository",
		"requiredItemIds": []any{"proofkit.adoption.profile"},
		"nextCommandRefs": []any{"agentic-proofkit adoption-workflow-plan --input proofkit/workflow.json"},
		"nonClaims":       []any{"Checklist test input does not prove merge readiness."},
		"items": []any{
			map[string]any{
				"blocker":      nil,
				"commandRefs":  []any{"agentic-proofkit scaffold-profile-plan --input proofkit/profile-scaffold.json"},
				"evidenceRefs": []any{"proofkit/repo-profile.v1.json"},
				"itemId":       "proofkit.adoption.profile",
				"label":        "Review repository profile scaffold.",
				"nonClaims":    []any{"Checklist item does not authenticate the profile file."},
				"owner":        "consumer-maintainers",
				"status":       "satisfied",
			},
			map[string]any{
				"blocker":      nil,
				"commandRefs":  []any{},
				"evidenceRefs": []any{},
				"itemId":       "proofkit.adoption.optional-release",
				"label":        "Review release channel evidence.",
				"nonClaims":    []any{"Optional release item does not block gradual adoption."},
				"owner":        "consumer-maintainers",
				"status":       "not_applicable",
			},
		},
	}
}

func firstChecklistItem(input map[string]any) map[string]any {
	return input["items"].([]any)[0].(map[string]any)
}

func checklistRuleMessageContains(results []report.RuleResult, needle string) bool {
	for _, result := range results {
		if strings.Contains(result.Message, needle) {
			return true
		}
	}
	return false
}
