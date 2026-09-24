package requirementsourcetransition

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildRejectsLifecycleTransitionWithoutNewEvidence(t *testing.T) {
	record, exitCode, err := Build(validRequirementSourceTransitionInput(false))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	record, exitCode, err = Build(validRequirementSourceTransitionInput(true))
	if err != nil {
		t.Fatalf("Build() lifecycle transition error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "removed requirement transition must declare new lifecycle evidenceRefs") {
		t.Fatalf("Build() accepted lifecycle transition without new evidence: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func TestBuildRejectsRequirementSourceTransitionContractViolations(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.055034508158962348386865908543647126084818400787416007817692072895213278443259")
	cases := []struct {
		name      string
		want      string
		wantRules map[string]string
		edit      func(previous map[string]any, next map[string]any)
	}{
		{
			name: "previous source admission failure stays separate",
			want: "previous source admission failed: active blocking requirement must route to proof bindings",
			wantRules: map[string]string{
				"proofkit.requirement-source-transition.boundary":           "passed",
				"proofkit.requirement-source-transition.source-admission":   "failed",
				"proofkit.requirement-source-transition.transition-lattice": "skipped",
			},
			edit: func(previous map[string]any, _ map[string]any) {
				firstRequirement(previous)["proofBindingRefs"] = []any{}
			},
		},
		{
			name: "next source admission failure stays separate",
			want: "next source admission failed: active blocking requirement must route to proof bindings",
			wantRules: map[string]string{
				"proofkit.requirement-source-transition.boundary":           "passed",
				"proofkit.requirement-source-transition.source-admission":   "failed",
				"proofkit.requirement-source-transition.transition-lattice": "skipped",
			},
			edit: func(_ map[string]any, next map[string]any) {
				firstRequirement(next)["proofBindingRefs"] = []any{}
			},
		},
		{
			name:      "source id drift",
			want:      "transition must compare the same requirement sourceId",
			wantRules: boundaryRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				next["sourceId"] = "proofkit.test.other_requirements"
			},
		},
		{
			name:      "spec package path drift",
			want:      "transition must compare the same specPackagePath",
			wantRules: boundaryRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				setPackage(next, "docs/specs/other-proofkit-test")
			},
		},
		{
			name:      "previous durable requirement missing",
			want:      "durable requirement must remain in next source before deletion",
			wantRules: latticeRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				next["groups"] = []any{}
			},
		},
		{
			name:      "new requirement starts non active",
			want:      "new requirement must start with active lifecycle",
			wantRules: latticeRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				appendRequirement(next, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-002",
					state:    "deprecated",
					evidence: []any{"docs/evidence/introduced-deprecated.md"},
				})
			},
		},
		{
			name:      "terminal removed state changes",
			want:      "terminal requirement lifecycle must not change",
			wantRules: latticeRuleStatuses(),
			edit: func(previous map[string]any, next map[string]any) {
				replaceRequirement(previous, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-001",
					state:    "removed",
					evidence: []any{"docs/evidence/removed.md"},
				})
				replaceRequirement(next, requirementFixture{
					id:    "REQ-PROOFKIT-TRANSITION-001",
					state: "active",
				})
			},
		},
		{
			name:      "terminal superseded replacements change",
			want:      "terminal superseded replacementRequirementIds must not change",
			wantRules: latticeRuleStatuses(),
			edit: func(previous map[string]any, next map[string]any) {
				replaceRequirement(previous, requirementFixture{
					id:           "REQ-PROOFKIT-TRANSITION-001",
					state:        "superseded",
					evidence:     []any{"docs/evidence/superseded.md"},
					replacements: []any{"REQ-PROOFKIT-TRANSITION-002"},
				})
				appendRequirement(previous, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-002", state: "active"})
				replaceRequirement(next, requirementFixture{
					id:           "REQ-PROOFKIT-TRANSITION-001",
					state:        "superseded",
					evidence:     []any{"docs/evidence/superseded.md"},
					replacements: []any{"REQ-PROOFKIT-TRANSITION-003"},
				})
				appendRequirement(next, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-002", state: "active"})
				appendRequirement(next, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-003", state: "active"})
			},
		},
		{
			name:      "deprecation requires new evidence",
			want:      "deprecated requirement transition must declare new lifecycle evidenceRefs",
			wantRules: latticeRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				replaceRequirement(next, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-001",
					state:    "deprecated",
					evidence: []any{"docs/evidence/previous.md"},
				})
			},
		},
		{
			name:      "removal requires new evidence",
			want:      "removed requirement transition must declare new lifecycle evidenceRefs",
			wantRules: latticeRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				replaceRequirement(next, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-001",
					state:    "removed",
					evidence: []any{"docs/evidence/previous.md"},
				})
			},
		},
		{
			name:      "supersession requires new evidence",
			want:      "superseded requirement transition must declare new lifecycle evidenceRefs",
			wantRules: latticeRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				replaceRequirement(next, requirementFixture{
					id:           "REQ-PROOFKIT-TRANSITION-001",
					state:        "superseded",
					evidence:     []any{"docs/evidence/previous.md"},
					replacements: []any{"REQ-PROOFKIT-TRANSITION-002"},
				})
				appendRequirement(next, requirementFixture{id: "REQ-PROOFKIT-TRANSITION-002", state: "active"})
			},
		},
		{
			name:      "reactivation requires new evidence",
			want:      "reactivated requirement transition must declare new lifecycle evidenceRefs",
			wantRules: latticeRuleStatuses(),
			edit: func(previous map[string]any, next map[string]any) {
				replaceRequirement(previous, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-001",
					state:    "deprecated",
					evidence: []any{"docs/evidence/previous.md"},
				})
				replaceRequirement(next, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-001",
					state:    "active",
					evidence: []any{"docs/evidence/previous.md"},
				})
			},
		},
		{
			name: "superseded replacement must be active in next source",
			want: "next source admission failed: replacement requirement must be active in the same source",
			wantRules: map[string]string{
				"proofkit.requirement-source-transition.boundary":           "passed",
				"proofkit.requirement-source-transition.source-admission":   "failed",
				"proofkit.requirement-source-transition.transition-lattice": "skipped",
			},
			edit: func(_ map[string]any, next map[string]any) {
				replaceRequirement(next, requirementFixture{
					id:           "REQ-PROOFKIT-TRANSITION-001",
					state:        "superseded",
					evidence:     []any{"docs/evidence/previous.md", "docs/evidence/superseded.md"},
					replacements: []any{"REQ-PROOFKIT-TRANSITION-002"},
				})
				appendRequirement(next, requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-002",
					state:    "deprecated",
					evidence: []any{"docs/evidence/deprecated.md"},
				})
			},
		},
		{
			name:      "prior lifecycle evidence is preserved",
			want:      "lifecycle evidenceRefs must preserve prior refs",
			wantRules: latticeRuleStatuses(),
			edit: func(_ map[string]any, next map[string]any) {
				replaceRequirement(next, requirementFixture{
					id:    "REQ-PROOFKIT-TRANSITION-001",
					state: "active",
				})
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			previous := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
			next := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
			item.edit(previous, next)

			record, exitCode, err := Build(transitionInput(previous, next))
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			encoded, _ := json.Marshal(record)
			if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), item.want) {
				t.Fatalf("Build() exitCode=%d state=%s record=%s, want failure containing %q", exitCode, record.State, string(encoded), item.want)
			}
			assertRuleStatuses(t, record.RuleResults, item.wantRules)
		})
	}
}

func validRequirementSourceTransitionInput(removeWithoutNewEvidence bool) map[string]any {
	previous := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
	next := transitionRequirementSource("active", []any{"docs/evidence/previous.md"})
	if removeWithoutNewEvidence {
		next = transitionRequirementSource("removed", []any{"docs/evidence/previous.md"})
	}
	return transitionInput(previous, next)
}

func transitionInput(previous map[string]any, next map[string]any) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"),
		"transitionId":  "proofkit.test.requirement-source-transition",
		"nonClaims":     []any{"Requirement source transition test input does not approve deletion."},
		"previous":      previous,
		"next":          next,
	}
}

type requirementFixture struct {
	evidence     []any
	id           string
	replacements []any
	state        string
}

func transitionRequirementSource(lifecycleState string, lifecycleEvidenceRefs []any) map[string]any {
	return map[string]any{
		"kind":            "proofkit.requirement-source",
		"schemaVersion":   json.Number("2"),
		"sourceId":        "proofkit.test.requirements",
		"specPackagePath": "docs/specs/proofkit-test",
		"sourceNonClaims": []any{"Requirement source transition fixture does not execute native witnesses."},
		"groups": []any{map[string]any{
			"groupId": "RGRP-TRANSITION", "profileId": "", "statementStem": "", "sharedPremises": []any{},
			"members": []any{
				requirementRecord(requirementFixture{
					id:       "REQ-PROOFKIT-TRANSITION-001",
					state:    lifecycleState,
					evidence: lifecycleEvidenceRefs,
				}),
			}}},
	}
}

func requirementRecord(item requirementFixture) map[string]any {
	claimLevel := "blocking"
	if item.state != "active" {
		claimLevel = "advisory"
	}
	evidence := item.evidence
	if evidence == nil {
		evidence = []any{}
	}
	replacements := item.replacements
	if replacements == nil {
		replacements = []any{}
	}
	return map[string]any{"requirementId": item.id, "statementCompletion": "Requirement source transition must preserve lifecycle evidence monotonicity.", "fields": map[string]any{
		"claimLevel": claimLevel,
		"deferral":   nil,
		"lifecycle": map[string]any{
			"evidenceRefs":              evidence,
			"replacementRequirementIds": replacements,
			"state":                     item.state,
		},
		"nonClaimRefs":         []any{},
		"externalNonClaimRefs": []any{},
		"nonClaims":            []any{"This requirement does not prove merge readiness."},
		"ownerId":              "proofkit.test",
		"proofBindingRefs": []any{
			"docs/contracts/requirement-proof-binding-sources.v1.json",
		},
		"riskClass": "medium",
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  true,
			"requiresProofBindingReview": true,
			"reviewOwnerId":              "proofkit.test",
		},
	}}
}

func firstRequirement(source map[string]any) map[string]any {
	return transitionMembers(source)[0].(map[string]any)["fields"].(map[string]any)
}

func transitionMembers(source map[string]any) []any {
	return source["groups"].([]any)[0].(map[string]any)["members"].([]any)
}

func replaceRequirement(source map[string]any, item requirementFixture) {
	requirements := transitionMembers(source)
	for index, value := range requirements {
		if value.(map[string]any)["requirementId"] == item.id {
			requirements[index] = requirementRecord(item)
			return
		}
	}
	appendRequirement(source, item)
}

func appendRequirement(source map[string]any, item requirementFixture) {
	source["groups"].([]any)[0].(map[string]any)["members"] = append(transitionMembers(source), requirementRecord(item))
}

func setPackage(source map[string]any, specPackagePath string) {
	source["specPackagePath"] = specPackagePath
}

func boundaryRuleStatuses() map[string]string {
	return map[string]string{
		"proofkit.requirement-source-transition.boundary":           "failed",
		"proofkit.requirement-source-transition.source-admission":   "passed",
		"proofkit.requirement-source-transition.transition-lattice": "skipped",
	}
}

func latticeRuleStatuses() map[string]string {
	return map[string]string{
		"proofkit.requirement-source-transition.boundary":           "passed",
		"proofkit.requirement-source-transition.source-admission":   "passed",
		"proofkit.requirement-source-transition.transition-lattice": "failed",
	}
}

func assertRuleStatuses(t *testing.T, rules []report.RuleResult, want map[string]string) {
	t.Helper()
	for ruleID, wantStatus := range want {
		found := false
		for _, rule := range rules {
			if rule.RuleID != ruleID {
				continue
			}
			found = true
			if rule.Status != wantStatus {
				t.Fatalf("%s status=%s, want %s", ruleID, rule.Status, wantStatus)
			}
		}
		if !found {
			t.Fatalf("missing rule %s", ruleID)
		}
	}
}
