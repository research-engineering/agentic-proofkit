package commandcoverage

import (
	"strings"
)

const semanticRoutePrefix = "proofkit.command_coverage.source_oracle.v1."
const ExecutionAttributeKey = "proofkit.command-oracle"

type testContext interface {
	Attr(string, string)
	Cleanup(func())
	Failed() bool
	Fatalf(string, ...any)
	Helper()
	Skipped() bool
}

// SemanticRoute binds one source-owned route marker to a cooperative runtime event.
// The event proves successful completion of the selected test, not execution of
// any particular assertion branch.
func SemanticRoute(t testContext, marker string) {
	t.Helper()
	if !ValidSourceMarker(marker) {
		t.Fatalf("invalid command coverage semantic route marker %q", marker)
		return
	}
	t.Cleanup(func() {
		if !t.Failed() && !t.Skipped() {
			t.Attr(ExecutionAttributeKey, marker)
		}
	})
}

func ValidSourceMarker(marker string) bool {
	if !strings.HasPrefix(marker, semanticRoutePrefix) || len(marker) != len(semanticRoutePrefix)+78 {
		return false
	}
	for _, character := range strings.TrimPrefix(marker, semanticRoutePrefix) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
