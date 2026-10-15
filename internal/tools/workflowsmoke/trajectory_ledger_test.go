package workflowsmoke

import (
	"context"
	"strings"
	"testing"
)

func TestTrajectoryLedgerRefusesUnnamedRoutesBeforeExecution(t *testing.T) {
	calls := 0
	session := newTrajectory(t.Context(), func(context.Context, Invocation) (Result, error) {
		calls++
		return Result{}, nil
	}, t.TempDir())
	for _, args := range [][]string{
		{"witness-plan", "--input", "-"},
		{"--json-layout", "compact", "status", "--repo-root", "x"},
		{"adopt", "plan", "--help"},
	} {
		if _, err := session.call("unnamed", unreadInvocation(args...)); err == nil || !strings.Contains(err.Error(), "was not named by an earlier CLI output") {
			t.Fatalf("unnamed route %v was not refused: %v", args, err)
		}
	}
	if calls != 0 {
		t.Fatalf("refused routes reached the carrier %d times", calls)
	}
	session.prefix = "agentic-proofkit"
	session.observe("guide", []byte("Usage:\n  run this:\n    agentic-proofkit witness-plan --input <projection-input>\n  prose mentions status --repo-root\n"))
	session.name("packet", []string{"adopt", "plan"})
	for _, args := range [][]string{{"witness-plan", "--input", "-"}, {"adopt", "plan", "--help"}} {
		if _, err := session.call("named", unreadInvocation(args...)); err != nil {
			t.Fatalf("named route %v was refused: %v", args, err)
		}
	}
	if _, err := session.call("prose only", unreadInvocation("status", "--repo-root", "x")); err == nil {
		t.Fatal("a route mentioned only in prose was treated as named")
	}
	if calls != 2 {
		t.Fatalf("named routes reached the carrier %d times, want 2", calls)
	}
}
