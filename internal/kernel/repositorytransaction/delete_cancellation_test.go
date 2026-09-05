package repositorytransaction

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func testDeletionCancellationCommitBoundary(t *testing.T) {
	for _, test := range []struct {
		name       string
		cancelAt   int
		cleanup    failurePoint
		state      string
		failure    string
		finalState string
	}{
		{"deleted-prefix", 1, "", StateRolledBack, "cancelled", StateRolledBack},
		{"final-effect", 3, "", StateApplied, "", StateApplied},
		{"final-effect-cleanup", 3, faultBeforeCleanup, StateCleanupRequired, "injected_cleanup_failure", StateApplied},
		{"final-effect-durability", 3, faultAfterStateRemoval, StateDurabilityUnknown, "applied_cleanup_durability_unknown", StateApplied},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			plan := seedDeletionRecovery(t, root)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cancelled := false
			runtime := engine{fault: func(point failurePoint, index int) error {
				if point == faultAfterPublish && index == test.cancelAt {
					cancelled = true
					cancel()
				}
				if test.cleanup != "" && point == test.cleanup {
					return errors.New("terminal cleanup failure")
				}
				return nil
			}}
			result, err := runtime.apply(ctx, root, plan)
			count := 3
			if test.finalState == StateRolledBack {
				count = 0
			}
			if !cancelled || ctx.Err() != context.Canceled || err != nil || result.State != test.state || result.FailureClass != test.failure || result.TransactionID != plan.TransactionID || !result.AppliedCountKnown || result.AppliedCount != count {
				t.Fatalf("cancellation crossed the commit boundary: %#v %v", result, err)
			}
			assertDeletionRecoveryFiles(t, root, test.finalState)
			action := RecoveryResume
			if test.finalState == StateRolledBack {
				action = RecoveryRollback
			}
			recovered, err := Recover(context.Background(), root, plan.TransactionID, action)
			if err != nil || recovered.State != test.finalState || recovered.TransactionID != plan.TransactionID || recovered.RecoveredBy != action {
				t.Fatalf("terminal recovery changed cancellation result: %#v %v", recovered, err)
			}
			assertDeletionRecoveryFiles(t, root, test.finalState)
			assertNoPendingTransaction(t, root)
			before := snapshotTestTree(t, root)
			replayed, err := Recover(context.Background(), root, plan.TransactionID, action)
			if err != nil || replayed != recovered || !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
				t.Fatalf("terminal retry changed the retained outcome: %#v %v", replayed, err)
			}
		})
	}
}
