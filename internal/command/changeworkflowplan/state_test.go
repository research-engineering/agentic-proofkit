package changeworkflowplan

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestWorkflowStatePredicates(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.046999593271228979057731418772803126658652333387186990019354835268016126566224")
	t.Run("checkpoint_requires_incomplete", func(t *testing.T) {
		input := terminalInput()
		input["checkpoint"] = map[string]any{"state": "not_started"}
		requireReject(t, input)
	})
	t.Run("complete_is_terminal", func(t *testing.T) {
		plan := requireBuild(t, terminalInput())
		if plan["outputKind"] != "workflow_complete" {
			t.Fatal("complete prefix is not terminal")
		}
	})
	t.Run("first_incomplete_active", func(t *testing.T) {
		for index, stage := range stageTable {
			plan := requireBuild(t, inputForStage(index, "not_started"))
			if plan["activeStageId"] != stage.ID {
				t.Fatalf("stage %d selected %v", index, plan["activeStageId"])
			}
		}
	})
	t.Run("incomplete_requires_checkpoint", func(t *testing.T) {
		input := initialInput()
		input["checkpoint"] = nil
		requireReject(t, input)
	})
	t.Run("prefix_only", func(t *testing.T) {
		input := initialInput()
		input["completedStageIds"] = []any{"design"}
		requireReject(t, input)
	})
	t.Run("stage_order", func(t *testing.T) {
		want := []string{"architecture", "design", "implementation_plan", "implementation", "verification", "pull_request", "closeout"}
		requireEqual(t, stageIDs(), want)
	})
	t.Run("terminal_omits_active_fields", func(t *testing.T) {
		plan := requireBuild(t, terminalInput())
		for _, key := range []string{"action", "activeStageId", "checkpointState", "prompt", "successorStateDelta"} {
			if _, exists := plan[key]; exists {
				t.Fatalf("terminal plan contains %s", key)
			}
		}
	})
}

func TestWorkflowCheckpointPredicates(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.057364505794091528940721933244472135772636722180139771802290163560593659249191")
	t.Run("closed_variants", func(t *testing.T) {
		for _, state := range []string{"not_started", "ready_for_review", "review_findings", "review_passed"} {
			if _, err := Build(inputForStage(0, state)); err != nil {
				t.Fatalf("closed variant %s rejected: %v", state, err)
			}
		}
		input := initialInput()
		input["checkpoint"] = map[string]any{"state": "pending"}
		requireReject(t, input)
	})
	t.Run("delta_exact_fields", func(t *testing.T) {
		plan := requireBuild(t, inputForStage(0, "review_passed"))
		delta := plan["successorStateDelta"].(map[string]any)
		if len(delta) != 2 {
			t.Fatalf("successor delta has %d fields", len(delta))
		}
	})
	t.Run("delta_preserves_context", func(t *testing.T) {
		prior := reviewInput("review_passed")
		plan := requireBuild(t, prior)
		merged, err := MergeSuccessor(prior, plan["successorStateDelta"].(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"schemaVersion", "governingAuthorityRefId", "contextRefs", "requiredContextRefIds"} {
			requireEqual(t, merged[key], prior[key])
		}
	})
	t.Run("illegal_fields_rejected", func(t *testing.T) {
		cases := []map[string]any{
			{"state": "not_started", "subjectRefId": "ctx.artifact"},
			{"state": "ready_for_review", "subjectRefId": "ctx.artifact"},
			{"state": "review_passed", "subjectRefId": "ctx.artifact", "subjectDigest": testDigest},
		}
		for _, checkpointValue := range cases {
			input := reviewInput("ready_for_review")
			input["checkpoint"] = checkpointValue
			requireReject(t, input)
		}
	})
	t.Run("merged_successor_admitted", func(t *testing.T) {
		for index := range stageTable {
			prior := inputForStage(index, "review_passed")
			plan := requireBuild(t, prior)
			merged, err := MergeSuccessor(prior, plan["successorStateDelta"].(map[string]any))
			if err != nil {
				t.Fatalf("stage %d successor rejected: %v", index, err)
			}
			if _, err := Build(merged); err != nil {
				t.Fatalf("stage %d merged successor rejected: %v", index, err)
			}
		}
	})
	t.Run("review_passed_accepts", func(t *testing.T) {
		for index := range stageTable {
			plan := requireBuild(t, inputForStage(index, "review_passed"))
			if plan["action"] != "accept_stage" {
				t.Fatalf("stage %d action is %v", index, plan["action"])
			}
		}
	})
	t.Run("terminal_disjoint", func(t *testing.T) {
		terminal := requireBuild(t, terminalInput())
		for index := range stageTable {
			for _, state := range []string{"not_started", "ready_for_review", "review_findings", "review_passed"} {
				active := requireBuild(t, inputForStage(index, state))
				if active["outputKind"] == terminal["outputKind"] {
					t.Fatal("active row overlaps terminal row")
				}
			}
		}
	})
	t.Run("twenty_eight_actions", func(t *testing.T) {
		if len(checkpointRelation) != 29 {
			t.Fatalf("relation has %d rows", len(checkpointRelation))
		}
		seen := 0
		for index := range stageTable {
			for _, state := range []string{"not_started", "ready_for_review", "review_findings", "review_passed"} {
				plan := requireBuild(t, inputForStage(index, state))
				if _, ok := plan["action"].(string); !ok {
					t.Fatal("active row has no action")
				}
				seen++
			}
		}
		if seen != 28 {
			t.Fatalf("got %d active rows", seen)
		}
	})
}
