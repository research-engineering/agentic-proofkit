package changeworkflowplan

import "testing"

func TestWorkflowPurityPredicates(t *testing.T) {
	t.Run("admit_once", func(t *testing.T) {
		input := initialInput()
		result, err := Project(input)
		if err != nil {
			t.Fatal(err)
		}
		input["completedStageIds"] = []any{"architecture"}
		if result.Plan["activeStageId"] != "architecture" {
			t.Fatal("projected result retained mutable caller input")
		}
	})
	t.Run("derived_non_authority", func(t *testing.T) {
		plan := requireBuild(t, initialInput())
		if plan["authority"] != "derived_non_authoritative_plan" {
			t.Fatal("plan does not deny semantic authority")
		}
		if len(plan["nonClaims"].([]any)) != len(boundaryNonClaims) {
			t.Fatal("plan lost boundary non-claims")
		}
		envelope, err := BuildAgentEnvelope(reviewInput("ready_for_review"))
		if err != nil {
			t.Fatal(err)
		}
		cost := envelope["costContract"].(map[string]any)
		if cost["referenceClosurePreserved"] != true || cost["prunedLocalReferenceCount"] != 0 {
			t.Fatalf("agent envelope lost local reference closure: %v", cost)
		}
	})
	t.Run("deterministic_output", func(t *testing.T) {
		input := reviewInput("review_passed")
		left, err := Project(input)
		if err != nil {
			t.Fatal(err)
		}
		right, err := Project(cloneMap(input))
		if err != nil {
			t.Fatal(err)
		}
		if canonical(t, left.Plan) != canonical(t, right.Plan) || left.Text != right.Text || canonical(t, left.AgentEnvelope) != canonical(t, right.AgentEnvelope) {
			t.Fatal("equal inputs produced unequal projections")
		}
	})
	t.Run("explicit_input", func(t *testing.T) {
		input := initialInput()
		input["repositoryRoot"] = "/tmp/repo"
		requireReject(t, input)
	})
	t.Run("no_execution", func(t *testing.T) {
		result := requireBuild(t, initialInput())
		if result["outputKind"] != "next_action" {
			t.Fatal("pure planner did not return its single projection")
		}
	})
	t.Run("single_output", func(t *testing.T) {
		active := requireBuild(t, initialInput())
		terminal := requireBuild(t, terminalInput())
		if active["outputKind"] != "next_action" || terminal["outputKind"] != "workflow_complete" {
			t.Fatal("output variants are not disjoint and total")
		}
	})
	t.Run("typed_decisions_only", func(t *testing.T) {
		input := initialInput()
		before := canonical(t, input)
		if _, err := Project(input); err != nil {
			t.Fatal(err)
		}
		if canonical(t, input) != before {
			t.Fatal("projection mutated caller input")
		}
	})
}
