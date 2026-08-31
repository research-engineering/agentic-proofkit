package changeworkflowplan

import (
	"strings"
	"testing"
)

func TestWorkflowTextPredicates(t *testing.T) {
	t.Run("planner_text_bound", func(t *testing.T) {
		result, err := Project(reviewInput("review_passed"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(result.Text, "\n"), "\n")
		if len(lines) > maxTextLines || len(result.Text) > maxTextBytes {
			t.Fatalf("text exceeds bounds: %d lines, %d bytes", len(lines), len(result.Text))
		}
		for _, coordinate := range []string{"architecture", "accept_stage", "review_passed", "ctx.authority", "successor_state_delta", "Omitted context: 1", "Non-claim:"} {
			if !strings.Contains(result.Text, coordinate) {
				t.Fatalf("text omits coordinate %q: %s", coordinate, result.Text)
			}
		}
	})
}

func TestWorkflowTextProjectionParity(t *testing.T) {
	input := reviewInput("review_passed")
	result, err := Project(input)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderText(result.TextLines)
	if err != nil {
		t.Fatal(err)
	}
	if rendered != result.Text {
		t.Fatalf("structured projection drifted from canonical text\ngot: %q\nwant: %q", rendered, result.Text)
	}
	if result.Text != "Change workflow plan\nOutput: next_action\nCompleted stages: none\nActive stage: architecture\nAction: accept_stage\nCheckpoint: review_passed\nOwner or escalation: ctx.authority\nStop condition: Stop after constructing the merged immutable snapshot; do not infer execution, approval, merge, or release from stage acceptance.\nExpected next checkpoint: successor_state_delta\nOmitted context: 1\nNon-claim: Change workflow plans do not approve repository edits, merge, release, rollout, or production readiness.\n" {
		t.Fatalf("canonical plain bytes changed: %q", result.Text)
	}
}

func TestWorkflowTerminalTextIsOperationallyComplete(t *testing.T) {
	result, err := Project(terminalInput())
	if err != nil {
		t.Fatal(err)
	}
	want := "Change workflow plan\nOutput: workflow_complete\nCompleted stages: architecture, design, implementation_plan, implementation, verification, pull_request, closeout\nCheckpoint: none\nOwner or escalation: consumer_repository\nStop condition: " + terminalStop + "\nExpected next checkpoint: none\nOmitted context: 0\nNon-claim: Change workflow plans do not approve repository edits, merge, release, rollout, or production readiness.\n"
	if result.Text != want {
		t.Fatalf("terminal text is not operationally complete: %q", result.Text)
	}
}

func TestWorkflowTextProjectionDefensiveCopy(t *testing.T) {
	input := initialInput()
	first, err := BuildTextProjection(input)
	if err != nil {
		t.Fatal(err)
	}
	first[0].Label = "mutated"
	second, err := BuildTextProjection(input)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Label != "Change workflow plan" {
		t.Fatal("text projection reused caller-mutated storage")
	}
	result, err := Project(input)
	if err != nil {
		t.Fatal(err)
	}
	result.TextLines[0].Label = "mutated again"
	if result.Text != "Change workflow plan\nOutput: next_action\nCompleted stages: none\nActive stage: architecture\nAction: author\nCheckpoint: not_started\nOwner or escalation: missing_consuming_repository_semantic_owner\nStop condition: Stop after the artifact and digest are ready for independent review. Do not mutate the repository until the caller supplies the consuming-repository semantic owner and governing authority coordinates.\nExpected next checkpoint: ready_for_review\nOmitted context: 0\nNon-claim: Change workflow plans do not approve repository edits, merge, release, rollout, or production readiness.\n" {
		t.Fatal("mutating structured projection changed canonical text bytes")
	}
}
