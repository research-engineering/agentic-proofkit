package requirementsourceview

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

func TestSourceViewCountersPreserveOwnerSummaryAndLiteralOutcomes(t *testing.T) {
	for _, item := range []struct {
		claim, lifecycle           string
		active, blocking, deferred int
	}{
		{"blocking", "active", 1, 1, 0},
		{"advisory", "active", 1, 0, 0},
		{"deferred", "active", 1, 0, 1},
		{"advisory", "deprecated", 0, 0, 0},
		{"advisory", "removed", 0, 0, 0},
		{"deferred", "deprecated", 0, 0, 1},
		{"advisory", "superseded", 1, 0, 0},
		{"deferred", "superseded", 1, 0, 1},
	} {
		t.Run(item.claim+"/"+item.lifecycle, func(t *testing.T) {
			input := validRequirementSource()
			fields := viewTestFields(input)
			fields["claimLevel"] = item.claim
			lifecycle := fields["lifecycle"].(map[string]any)
			lifecycle["state"] = item.lifecycle
			if item.lifecycle != "active" {
				lifecycle["evidenceRefs"] = []any{"review.history"}
			}
			if item.lifecycle == "superseded" {
				replacement := viewTestMember(validRequirementSource())
				replacement["requirementId"] = "REQ-PROOFKIT-VIEW-002"
				replacement["fields"].(map[string]any)["claimLevel"] = "advisory"
				group := input["groups"].([]any)[0].(map[string]any)
				group["members"] = append(group["members"].([]any), replacement)
				lifecycle["replacementRequirementIds"] = []any{"REQ-PROOFKIT-VIEW-002"}
			}
			if item.claim == "deferred" {
				fields["deferral"] = map[string]any{
					"ownerId": "owner.review", "riskAcceptedBy": "owner.risk", "reviewCondition": "Review the declared change.",
					"expiryRef": "review.next", "mergePolicy": "policy.review", "evidenceRefs": []any{"review.evidence"},
				}
			}
			admitted, err := requirementsourceadmission.Evaluate(input)
			if err != nil || admitted.ExitCode != 0 {
				t.Fatalf("admission: %v, %v", err, admitted.Failures)
			}
			value, exit, err := BuildJSON(input)
			if err != nil || exit != 0 {
				t.Fatalf("view: %v, exit %d", err, exit)
			}
			view := value.(map[string]any)
			for _, count := range []struct {
				name           string
				literal, owner int
			}{
				{"activeRequirementCount", item.active, admitted.Summary.ActiveRequirementCount},
				{"blockingRequirementCount", item.blocking, admitted.Summary.BlockingRequirementCount},
				{"deferredRequirementCount", item.deferred, admitted.Summary.DeferredRequirementCount},
			} {
				if view[count.name] != count.literal || view[count.name] != count.owner {
					t.Fatalf("%s=%v owner=%d want=%d", count.name, view[count.name], count.owner, count.literal)
				}
			}
			if view["requirementCount"] != len(view["requirements"].([]any)) || view["requirementCount"] != admitted.Summary.RequirementCount {
				t.Fatal("view row count differs from its admitted source")
			}
		})
	}
	input := validRequirementSource()
	viewTestFields(input)["lifecycle"] = map[string]any{"state": "removed", "evidenceRefs": []any{"review.history"}}
	if value, exit, err := BuildJSON(input); err == nil || exit != 1 || value != nil {
		t.Fatal("inactive blocking requirement produced a usable source view")
	}
}
