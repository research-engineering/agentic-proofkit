package commandcoverage

import (
	"strings"
	"testing"
)

const semanticRoutePrefix = "proofkit.command_coverage.source_oracle.v1."

// SemanticRoute validates a legacy source marker for a proof-route candidate.
// It does not execute a falsification event or produce semantic evidence.
func SemanticRoute(t testing.TB, marker string) {
	t.Helper()
	if !strings.HasPrefix(marker, semanticRoutePrefix) || len(marker) != len(semanticRoutePrefix)+78 {
		t.Fatalf("invalid command coverage semantic route marker %q", marker)
	}
	for _, character := range strings.TrimPrefix(marker, semanticRoutePrefix) {
		if character < '0' || character > '9' {
			t.Fatalf("invalid command coverage semantic route marker %q", marker)
		}
	}
}
