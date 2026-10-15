package projectstatus

import (
	"slices"
	"testing"
)

// Every reachable action class has exactly one continuation, and a class
// whose packet names a command route continues with that same route's help.
func TestActionContinuationsMatchTheCanonicalActionTable(t *testing.T) {
	cases := []struct {
		state      ProjectState
		issues     []string
		contextRef string
	}{
		{StateUninitialized, []string{IssueManifestMissing}, ""},
		{StateStale, []string{IssueChildDigestMismatch}, "sha256:context"},
		{StateRecoveryRequired, []string{IssueTransactionRecoveryRequired}, "sha256:context"},
		{StateVerificationRequired, []string{}, "sha256:context"},
		{StateBlocked, []string{IssueTransactionInvalid}, ""},
		{StateBlocked, []string{IssueManifestInvalid}, ""},
	}
	covered := []string{}
	for _, item := range cases {
		action, err := canonicalAction(item.state, item.issues, item.contextRef)
		if err != nil {
			t.Fatalf("canonical action %s: %v", item.state, err)
		}
		matches := 0
		for _, continuation := range actionContinuations {
			if continuation.ActionClass != action.ActionClass {
				continue
			}
			matches++
			if len(action.CommandRoute) > 0 && !slices.Equal(continuation.HelpRoute, action.CommandRoute) {
				t.Fatalf("%s continues with %v, want its packet route %v", action.ActionClass, continuation.HelpRoute, action.CommandRoute)
			}
			if action.ActionClass == ActionRunRepositoryVerification && !slices.Equal(continuation.HelpRoute, []string{"native-evidence-guidance"}) {
				t.Fatalf("verification continues with %v", continuation.HelpRoute)
			}
		}
		if matches != 1 {
			t.Fatalf("%s has %d continuations, want 1", action.ActionClass, matches)
		}
		covered = append(covered, action.ActionClass)
	}
	slices.Sort(covered)
	listed := []string{}
	for _, continuation := range actionContinuations {
		listed = append(listed, continuation.ActionClass)
	}
	slices.Sort(listed)
	if !slices.Equal(covered, listed) {
		t.Fatalf("continuations %v do not equal reachable action classes %v", listed, covered)
	}
}
