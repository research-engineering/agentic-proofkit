package changeworkflowplan

import (
	"fmt"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

type expectedWorkflowRow struct {
	StageIndex      int
	StageID         string
	CheckpointState string
	Action          string
	OutputKind      string
}

var expectedWorkflowStateMatrix = []expectedWorkflowRow{
	{0, "architecture", "not_started", "author", "next_action"},
	{0, "architecture", "ready_for_review", "review", "next_action"},
	{0, "architecture", "review_findings", "repair", "next_action"},
	{0, "architecture", "review_passed", "accept_stage", "next_action"},
	{1, "design", "not_started", "author", "next_action"},
	{1, "design", "ready_for_review", "review", "next_action"},
	{1, "design", "review_findings", "repair", "next_action"},
	{1, "design", "review_passed", "accept_stage", "next_action"},
	{2, "implementation_plan", "not_started", "author", "next_action"},
	{2, "implementation_plan", "ready_for_review", "review", "next_action"},
	{2, "implementation_plan", "review_findings", "repair", "next_action"},
	{2, "implementation_plan", "review_passed", "accept_stage", "next_action"},
	{3, "implementation", "not_started", "implement", "next_action"},
	{3, "implementation", "ready_for_review", "review", "next_action"},
	{3, "implementation", "review_findings", "repair", "next_action"},
	{3, "implementation", "review_passed", "accept_stage", "next_action"},
	{4, "verification", "not_started", "verify", "next_action"},
	{4, "verification", "ready_for_review", "review", "next_action"},
	{4, "verification", "review_findings", "repair", "next_action"},
	{4, "verification", "review_passed", "accept_stage", "next_action"},
	{5, "pull_request", "not_started", "open_pull_request", "next_action"},
	{5, "pull_request", "ready_for_review", "review", "next_action"},
	{5, "pull_request", "review_findings", "repair", "next_action"},
	{5, "pull_request", "review_passed", "accept_stage", "next_action"},
	{6, "closeout", "not_started", "closeout", "next_action"},
	{6, "closeout", "ready_for_review", "review", "next_action"},
	{6, "closeout", "review_findings", "repair", "next_action"},
	{6, "closeout", "review_passed", "accept_stage", "next_action"},
	{-1, "", "", "", "workflow_complete"},
}

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
		for index, stage := range workflowCatalog.Stages {
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
		for index := range workflowCatalog.Stages {
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
	t.Run("agent_envelope_transition_is_executable", func(t *testing.T) {
		for index := range workflowCatalog.Stages {
			prior := inputForStage(index, "review_passed")
			envelope, err := BuildAgentEnvelope(prior)
			if err != nil {
				t.Fatalf("stage %d envelope rejected: %v", index, err)
			}
			actions := envelope["actionPlan"].([]any)
			if len(actions) != 1 {
				t.Fatalf("stage %d action count=%d, want 1", index, len(actions))
			}
			action := actions[0].(map[string]any)
			if action["outputKind"] != "next_action" {
				t.Fatalf("stage %d outputKind=%v", index, action["outputKind"])
			}
			delta, ok := action["successorStateDelta"].(map[string]any)
			if !ok {
				t.Fatalf("stage %d envelope omits successorStateDelta: %v", index, action)
			}
			merged, err := MergeSuccessor(prior, delta)
			if err != nil {
				t.Fatalf("stage %d envelope delta rejected: %v", index, err)
			}
			if _, err := Build(merged); err != nil {
				t.Fatalf("stage %d envelope successor rejected: %v", index, err)
			}
		}
	})
	t.Run("agent_envelope_terminal_is_explicit", func(t *testing.T) {
		envelope, err := BuildAgentEnvelope(terminalInput())
		if err != nil {
			t.Fatal(err)
		}
		actions := envelope["actionPlan"].([]any)
		if len(actions) != 1 {
			t.Fatalf("terminal action count=%d, want 1", len(actions))
		}
		action := actions[0].(map[string]any)
		if action["outputKind"] != "workflow_complete" || action["phase"] != "terminal" {
			t.Fatalf("terminal action is not explicit: %v", action)
		}
		if _, present := action["successorStateDelta"]; present {
			t.Fatalf("terminal action contains successorStateDelta: %v", action)
		}
	})
	t.Run("review_passed_accepts", func(t *testing.T) {
		for index := range workflowCatalog.Stages {
			plan := requireBuild(t, inputForStage(index, "review_passed"))
			if plan["action"] != "accept_stage" {
				t.Fatalf("stage %d action is %v", index, plan["action"])
			}
		}
	})
	t.Run("terminal_disjoint", func(t *testing.T) {
		terminal := requireBuild(t, terminalInput())
		for index := range workflowCatalog.Stages {
			for _, state := range []string{"not_started", "ready_for_review", "review_findings", "review_passed"} {
				active := requireBuild(t, inputForStage(index, state))
				if active["outputKind"] == terminal["outputKind"] {
					t.Fatal("active row overlaps terminal row")
				}
			}
		}
	})
	t.Run("independent_twenty_nine_row_matrix", func(t *testing.T) {
		if len(checkpointRelation) != len(expectedWorkflowStateMatrix) {
			t.Fatalf("relation has %d rows, want %d", len(checkpointRelation), len(expectedWorkflowStateMatrix))
		}
		seen := map[string]struct{}{}
		for _, expected := range expectedWorkflowStateMatrix {
			name := expected.OutputKind
			input := terminalInput()
			if expected.StageIndex >= 0 {
				name = fmt.Sprintf("%02d/%s", expected.StageIndex, expected.CheckpointState)
				input = inputForStage(expected.StageIndex, expected.CheckpointState)
			}
			t.Run(name, func(t *testing.T) {
				plan := requireBuild(t, input)
				if plan["outputKind"] != expected.OutputKind {
					t.Fatalf("outputKind=%v want %s", plan["outputKind"], expected.OutputKind)
				}
				if expected.StageIndex < 0 {
					if _, present := plan["action"]; present {
						t.Fatalf("terminal plan contains action: %v", plan)
					}
					return
				}
				key := expected.StageID + "|" + expected.CheckpointState
				if _, duplicate := seen[key]; duplicate {
					t.Fatalf("duplicate expected matrix row %s", key)
				}
				seen[key] = struct{}{}
				if plan["activeStageId"] != expected.StageID || plan["checkpointState"] != expected.CheckpointState || plan["action"] != expected.Action {
					t.Fatalf("plan coordinates=%v/%v/%v want %s/%s/%s", plan["activeStageId"], plan["checkpointState"], plan["action"], expected.StageID, expected.CheckpointState, expected.Action)
				}
			})
		}
		if len(seen) != 28 {
			t.Fatalf("matrix has %d unique active rows, want 28", len(seen))
		}
	})
}
